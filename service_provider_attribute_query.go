package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// MakeAttributeQuery produces a new AttributeQuery to send to the IdP's attribute query endpoint.
func (sp *ServiceProvider) MakeAttributeQuery(idpURL, nameID string, attributes []Attribute) (*AttributeQuery, error) {
	aq := AttributeQuery{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  idpURL,
		// Consent:      "", // TODO see http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §8.4
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(sp.EntityID, sp.MetadataURL.String()),
		},
		Subject: &Subject{
			NameID: &NameID{
				Format:          sp.nameIDFormat(),
				Value:           nameID,
				NameQualifier:   sp.IDPMetadata.EntityID,
				SPNameQualifier: sp.Metadata().EntityID,
			},
		},
		Attributes: attributes,
	}

	if len(sp.SignatureMethod) > 0 {
		if err := sp.SignAttributeQuery(&aq); err != nil {
			return nil, fmt.Errorf("signing attribute query: %w", err)
		}
	}
	return &aq, nil
}

// SignAttributeQuery adds the `Signature` element to the `AttributeRequest`.
func (sp *ServiceProvider) SignAttributeQuery(req *AttributeQuery) error {
	signingContext, err := GetSigningContext(sp)
	if err != nil {
		return err
	}

	signedRequestEl, err := signingContext.SignEnveloped(req.Element())
	if err != nil {
		return err
	}

	sigEl := signedRequestEl.Child[len(signedRequestEl.Child)-1]
	req.Signature = sigEl.(*etree.Element)
	return nil
}

// ParseXMLAttributeQueryResponse validates the SAML AttributeQuery response
// and returns the verified assertion.
//
// This function handles verifying the digital signature, and verifying
// that the specified conditions and properties are met.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure of diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseXMLAttributeQueryResponse(decodedResponseXML []byte, requestID string) (*Assertion, error) {
	now := TimeNow()
	// var err error
	retErr := &InvalidResponseError{
		Now:      now,
		Response: string(decodedResponseXML),
	}

	// ensure that the response XML is well formed before we parse it
	if err := xrv.Validate(bytes.NewReader(decodedResponseXML)); err != nil {
		retErr.PrivateErr = fmt.Errorf("invalid xml: %s", err)
		return nil, retErr
	}

	envelope := &struct {
		XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
		Body    struct {
			Response Response
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}{}
	if err := xml.Unmarshal(decodedResponseXML, &envelope); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}

	resp := envelope.Body.Response

	// Validate ArtifactResponse
	if resp.InResponseTo != requestID {
		retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match the artifact request ID (expected %v)", requestID)
		return nil, retErr
	}
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		retErr.PrivateErr = fmt.Errorf("response IssueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
		return nil, retErr
	}
	if resp.Issuer != nil && resp.Issuer.Value != sp.IDPMetadata.EntityID {
		retErr.PrivateErr = fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
		return nil, retErr
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		status := resp.Status.StatusCode.Value
		for code := resp.Status.StatusCode.StatusCode; code != nil; code = code.StatusCode {
			status += fmt.Sprintf(" %s", code.Value)
		}
		retErr.PrivateErr = ErrBadStatus{Status: status}
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decodedResponseXML); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	responseEl := doc.FindElement("Envelope/Body/Response")
	if responseEl == nil {
		retErr.PrivateErr = fmt.Errorf("missing inner Response")
		return nil, retErr
	}

	assertion, updatedResponse, err := sp.validateXMLResponse(&resp, responseEl, []string{requestID}, now, true)
	if err != nil {
		retErr.PrivateErr = err
		if updatedResponse != nil {
			retErr.Response = *updatedResponse
		}
		return nil, retErr
	}

	return assertion, nil
}

// AttributeQuery performs an attribute query against the identity provider and returns the verified assertion.
func (sp *ServiceProvider) AttributeQuery(nameID string, attributes []Attribute) (*Assertion, error) {
	aq, err := sp.MakeAttributeQuery(sp.GetAttributeQueryEndpoint(), nameID, attributes)
	if err != nil {
		return nil, fmt.Errorf("making attribute query: %w", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(aq.SoapRequest())

	var requestBuffer bytes.Buffer
	if _, err := doc.WriteTo(&requestBuffer); err != nil {
		return nil, fmt.Errorf("writing to request buffer: %w", err)
	}

	client := sp.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Post(sp.GetAttributeQueryEndpoint(), "text/xml", &requestBuffer)
	if err != nil {
		return nil, fmt.Errorf("making SOAP post request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("non-OK status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	attributeQueryResponse, err := sp.ParseXMLAttributeQueryResponse(body, aq.ID)
	if err != nil {
		return nil, fmt.Errorf("parsing attribute query response: %w", err)
	}
	return attributeQueryResponse, nil
}

// GetAttributeQueryEndpoint returns URL for the IDP's
// AttributeQuery endpoint of the specified type.
func (sp *ServiceProvider) GetAttributeQueryEndpoint() string {
	for _, idpAttributeAuthorityDescriptor := range sp.IDPMetadata.AttributeAuthorityDescriptors {
		for _, attributeService := range idpAttributeAuthorityDescriptor.AttributeServices {
			if attributeService.Binding == SOAPBinding {
				return attributeService.Location
			}
		}
	}
	return ""
}
