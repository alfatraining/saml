package saml

import (
	"encoding/xml"
	"time"

	"github.com/beevik/etree"
)

// AttributeQuery represents the SAML object of the same name, a request from a service provider
// to retrieve attributes of a subject.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeQuery struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AttributeQuery"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	Subject    *Subject    // TODO sequence also possible
	Attributes []Attribute `xml:"Attribute"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *AttributeQuery) Element() *etree.Element {
	el := etree.NewElement("samlp:AttributeQuery")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", r.IssueInstant.Format(timeFormat))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}
	for _, v := range r.Attributes {
		el.AddChild(v.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (r *AttributeQuery) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AttributeQuery
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// SoapRequest returns a SOAP Envelope containing the AttributeQuery request
func (r *AttributeQuery) SoapRequest() *etree.Element {
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	body := etree.NewElement("soapenv:Body")
	envelope.AddChild(body)
	body.AddChild(r.Element())
	return envelope
}
