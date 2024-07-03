---
v: 3

title: Ephemeral Diffie-Hellman Over COSE (EDHOC) and Object Security for Constrained Environments (OSCORE) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: EDHOC and OSCORE profile of ACE
docname: draft-ietf-ace-edhoc-oscore-profile-latest
category: std
submissiontype: IETF

venue:
  group: Authentication and Authorization for Constrained Environments (ace)
  mail: ace@ietf.org
  github: ace-wg/ace-edhoc-oscore-profile

ipr: trust200902
area: Security
workgroup: ACE Working Group
keyword: Internet-Draft

coding: utf-8

author:
-
    ins: G. Selander
    name: Göran Selander
    org: Ericsson
    email: goran.selander@ericsson.com
-
    ins: J. Preuß Mattsson
    name: John Preuß Mattsson
    org: Ericsson
    email: john.mattsson@ericsson.com
-
    ins: M. Tiloca
    name: Marco Tiloca
    org: RISE
    email: marco.tiloca@ri.se
-
    ins: R. Höglund
    name: Rikard Höglund
    org: RISE
    email: rikard.hoglund@ri.se

normative:
  RFC3986:
  RFC4648:
  RFC5280:
  RFC6749:
  RFC7120:
  RFC7252:
  RFC7515:
  RFC7519:
  RFC7800:
  RFC8126:
  RFC8392:
  RFC8610:
  RFC8613:
  RFC8742:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9200:
  RFC9201:
  RFC9203:
  RFC9360:
  RFC9528:
  I-D.ietf-core-oscore-edhoc:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-ace-workflow-and-params:
  COSE.Header.Parameters:
    author:
      org: IANA
    date: false
    title: COSE Header Parameters
    target: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters

informative:
  RFC4949:
  RFC8446:
  RFC9110:
  RFC9147:
  I-D.ietf-core-oscore-key-update:
  I-D.ietf-lake-authz:
  I-D.ietf-ace-coap-est-oscore:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework.
It utilizes Ephemeral Diffie-Hellman Over COSE (EDHOC) for achieving mutual authentication between an ACE-OAuth Client and Resource Server, and it binds an authentication credential of the Client to an ACE-OAuth access token.
EDHOC also establishes an Object Security for Constrained RESTful Environments (OSCORE) Security Context, which is used to secure communications when accessing protected resources according to the authorization information indicated in the access token.
This profile can be used to delegate management of authorization information from a resource-constrained server to a trusted host with less severe limitations regarding processing power and memory.

--- middle


# Introduction

This document defines the "coap_edhoc_oscore" profile of the ACE-OAuth framework {{RFC9200}}. This profile addresses a "zero-touch" constrained setting where authenticated and authorized operations can be performed with low overhead without endpoint specific configurations.

Like in the "coap_oscore" profile {{RFC9203}}, also in this profile a client (C) and a resource server (RS) use the Constrained Application Protocol (CoAP) {{RFC7252}} to communicate, and Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} to protect their communications, but this profile uses the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol {{RFC9528}} to establish the OSCORE Security Context. The processing of requests for specific protected resources is identical to what is defined in the "coap_oscore" profile.

When using this profile, C accesses protected resources hosted at RS with the use of an access token issued by a trusted authorization server (AS) and bound to an authentication credential of C. This differs from the "coap_oscore" profile, where the access token is bound to a symmetric key used to derive the OSCORE Security Context. As recommended in {{RFC9200}}, this document recommends the use of CBOR Web Tokens (CWTs) {{RFC8392}} as access tokens.

An authentication credential can be a raw public key, e.g., encoded as a CWT Claims Set (CCS, {{RFC8392}}); or a public key certificate, e.g., encoded as an X.509 certificate {{RFC5280}} or as a CBOR encoded X.509 certificate (C509, {{I-D.ietf-cose-cbor-encoded-cert}}); or a different type of data structure containing the public key of the peer in question.

The ACE protocol establishes what those authentication credentials are, and may transport the actual authentication credentials by value or uniquely refer to them. If an authentication credential is pre-provisioned or can be obtained over less constrained links, then it suffices that ACE provides a unique reference such as a certificate hash (e.g., by using the COSE header parameter "x5t", see {{RFC9360}}). This is in the same spirit as EDHOC, where the authentication credentials may be transported or referenced in the ID_CRED_x message fields (see {{Section 3.5.3 of RFC9528}}).

In general, AS and RS are likely to have trusted access to each other's authentication credentials, since AS acts on behalf of RS as per the trust model of ACE. Also, AS needs to have some information about C, including the relevant authentication credential, in order to identify C when it requests an access token and to determine what access rights it can be granted. However, the authentication credential of C may potentially be conveyed (or uniquely referred to) within the request for access that C makes to AS.

The establishment of an association between RS and AS in an ACE ecosystem is out of scope, but one solution is to build on the same primitives as used in this document, i.e., EDHOC for authentication and OSCORE for communication security, using for example {{I-D.ietf-lake-authz}} for onboarding RS with AS, and {{I-D.ietf-ace-coap-est-oscore}} for establishing a trust anchor in RS. A similar procedure can also be applied between C and AS for registering a client and for the establishment of a trust anchor.

## Terminology # {#terminology}

{::boilerplate bcp14-tagged}

Certain security-related terms such as "authentication", "authorization", "confidentiality", "(data) integrity", "Message Authentication Code (MAC)", "Hash-based Message Authentication Code (HMAC)", and "verify" are taken from {{RFC4949}}.

RESTful terminology follows HTTP {{RFC9110}}.

Readers are expected to be familiar with the terms and concepts defined in CoAP {{RFC7252}}, OSCORE {{RFC8613}}, and EDHOC {{RFC9528}}.

Readers are also expected to be familiar with the terms and concepts of the ACE framework described in {{RFC9200}} and in {{RFC9201}}.

Terminology for entities in the architecture is defined in OAuth 2.0 {{RFC6749}}, such as the client (C), the resource server (RS), and the authorization server (AS).  It is assumed in this document that a given resource on a specific RS is associated with a unique AS.

Note that the term "endpoint" is used here, as in {{RFC9200}}, following its OAuth definition, which is to denote resources such as /token and /introspect at AS and /authz-info at RS. The CoAP {{RFC7252}} definition, which is "An entity participating in the CoAP protocol" is not used in this document.

The authorization information (authz-info) resource refers to the authorization information endpoint as specified in {{RFC9200}}. The term "claim" is used in this document with the same semantics as in {{RFC9200}}, i.e., it denotes information carried in the access token or returned from introspection.

Concise Binary Object Representation (CBOR) {{RFC8949}}{{RFC8742}} and Concise Data Definition Language (CDDL) {{RFC8610}} are used in this document. CDDL predefined type names, especially bstr for CBOR byte strings and tstr for CBOR text strings, are used extensively in this document.

Examples throughout this document are expressed in CBOR diagnostic notation as defined in {{Section 8 of RFC8949}} and {{Appendix G of RFC8610}}. Diagnostic notation comments are often used to provide a textual representation of the numeric parameter names and values.

In the CBOR diagnostic notation used in this document, constructs of the form e'SOME_NAME' are replaced by the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. For example, {e'session_id' : h'01', e'cipher_suites': 3} stands for {0 : h'01', 2 : 3}.

Note to RFC Editor: Please delete the paragraph immediately preceding this note. Also, in the CBOR diagnostic notation used in this document, please replace the constructs of the form e'SOME_NAME' with the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. Finally, please delete this note.

# Protocol Overview {#overview}

This section gives an overview of how to use the ACE framework {{RFC9200}} together with the lightweight authenticated key exchange protocol EDHOC {{RFC9528}}. By doing so, the client (C) and the resource server (RS) generate an OSCORE Security Context {{RFC8613}} associated with authorization information, and use that security context to protect their communications. The parameters needed by C to negotiate the use of this profile with the authorization server (AS), as well as the OSCORE setup process, are described in detail in the following sections.

RS maintains a collection of authentication credentials. These are associated with OSCORE Security Contexts and with authorization information for all clients that RS is communicating with. The authorization information is used to enforce polices for processing requests from those clients.

The ACE framework describes how the authorization information propagates from AS to RS. This profile specifies how C requests an access token, including  authorization information, from AS for the resources it wants to access on RS, by sending an access token request to the /token endpoint, as specified in {{Section 5.8 of RFC9200}}.

If the request is granted then AS may send back an access token in a response to C, or upload the access token directly to RS as described in the alternative workflow defined in {{I-D.ietf-ace-workflow-and-params}}. The latter is not detailed further here.

If C has retrieved an access token, there are two options for C to upload it to RS, as further detailed later in the document.

1. C posts the access token to the /authz-info endpoint by using the mechanisms specified in {{Section 5.10 of RFC9200}}. If the access token is valid, RS replies to the request with a 2.01 (Created) response, after which C initiates the EDHOC protocol with RS. The communication with the /authz-info endpoint may not be protected unless there is previously established security context, for example in the case of update of access rights, see {{update-access-rights-c-rs}}.

2. C initiates the EDHOC protocol and includes the access token as External Authorization Data (EAD), see {{Section 3.8 of RFC9528}}. In this case, the access token is validated in parallel with the EDHOC session. The EAD item containing the access token is protected in different ways depending on which EDHOC message it is carried in, see {{Section 9.1 of RFC9528}}.

When running the EDHOC protocol, C uses the authentication credential of RS specified by AS together with the access token, while RS uses the authentication credential of C bound to and specified within the access token. If C and RS complete the EDHOC session successfully, they are mutually authenticated and they derive an OSCORE Security Context as per {{Section A.1 of RFC9528}}.

From then on, C effectively gains authorized and secure access to protected resources on RS with the established OSCORE Security Context, for as long as there is a valid access token. The OSCORE Security Context is discarded when an access token (whether the same or a different one) is used to successfully derive a new OSCORE Security Context for C.

While the OSCORE Security Context and access token are valid, C can contact AS to request an update of its access rights, by sending a similar request to the /token endpoint. This request also includes a "session identifier" (see {{edhoc-parameters-object}}) provided by AS in the initial request, which allows AS to find the data it has previously shared with C. The session identifier is assigned by AS and used to identify a series of access tokens, called a "token series" (see {{token-series}}). Upon successful update of access rights (see {{update-access-rights-c-rs}}), the new issued access token becomes the latest in its token series, but the session identifier remains the same. When the latest access token of a token series becomes invalid (e.g., when it expires or gets revoked), that token series ends.

When RS receives a request from C protected with an OSCORE Security Context derived from an EDHOC session implementing this profile, then the associated session identifier, together with the authentication credential of C used in the EDHOC session, enables the RS to look up the unique access token determining the access rights of C.

Comparing the options above: In option 1 the token upload and the EDHOC protocol is performed in series, which requires more messages exchanged than option 2. An overview of the message flow for the "coap_edhoc_oscore" profile in case of option 1 above is given in {{protocol-overview}}, and a more detailed protocol is provided in {{example-without-optimization}}. For option 2, the EDHOC protocol, access token upload, and access request & response can be completed in two round trips, see {{example-with-optimization}}.

Option 1 supports update of access rights protected with the existing OSCORE Security Context, see {{update-access-rights-c-rs}}, whereas option 2 always generates a new OSCORE Security Context. In case of option 2, in order to support update of access rights without changing OSCORE Security Context, C need to also implement option 1 or rely on some other method, such as the alternative workflow, see {{I-D.ietf-ace-workflow-and-params}}.


~~~~~~~~~~~ aasvg

   C                            RS                       AS
   |                            |                         |
   | <==== Mutual authentication and secure channel ====> |
   |                            |                         |
   | ------- POST /token  ------------------------------> |
   |                            |                         |
   | <-------------------------------- Access Token ----- |
   |                               + Access Information   |
   |                            |                         |
   | ---- POST /authz-info ---> |                         |
   |       (access_token)       |                         |
   |                            |                         |
   | <----- 2.01 Created ------ |                         |
   |                            |                         |
   | <========= EDHOC ========> |                         |
   |  Mutual authentication     |                         |
   |  and derivation of an      |                         |
   |  OSCORE Security Context   |                         |
   |                            |                         |
   |                /Proof-of-possession and              |
   |                Security Context storage/             |
   |                            |                         |
   | ---- OSCORE Request -----> |                         |
   |                            |                         |
   | <--- OSCORE Response ----- |                         |
   |                            |                         |
/Proof-of-possession            |                         |
and Security Context            |                         |
storage (latest)/               |                         |
   |                            |                         |
   | ---- OSCORE Request -----> |                         |
   |                            |                         |
   | <--- OSCORE Response ----- |                         |
   |                            |                         |
   |           ...              |                         |

~~~~~~~~~~~
{: #protocol-overview title="Protocol Overview Example. Names of messages coincide with those of RFC 9200 when applicable."}


# Client-AS Communication # {#c-as-comm}

The following subsections describe the details of the POST request and response to the /token endpoint between C and AS.

In this exchange, AS provides C with the access token, together with a set of parameters that enable C to run EDHOC with RS. In particular, these include information about the authorization credential of RS, AUTH\_CRED\_RS, transported by value or uniquely referred to.

The access token is securely associated with the authentication credential of C, AUTH\_CRED\_C, by including it or uniquely referring to it in the access token.

AUTH\_CRED\_C is specified in the "req_cnf" parameter defined in {{RFC9201}} of the POST request to the /token endpoint from C to AS, either transported by value or uniquely referred to.

The request to the /token endpoint and the corresponding response can include EDHOC\_Information, which is a CBOR map object containing information related to an EDHOC session, in particular the identifier "session\_id", see {{edhoc-parameters-object}}. This object is transported in the "edhoc\_info" parameter registered in {{iana-oauth-params}} and {{iana-oauth-cbor-mappings}}.

## C-to-AS: POST to /token endpoint # {#c-as}

The client-to-AS request is specified in {{Section 5.8.1 of RFC9200}}.

The client MUST send this POST request to the /token endpoint over a secure channel that guarantees authentication, message integrity, and confidentiality (see {{secure-comm-as}}). This document describes the use of CoAP, EDHOC and OSCORE to reduce the number of libraries that C has to support.

An example of such a request is shown in {{token-request}}. In this example, C specifies its own authentication credential by reference, as the hash of an X.509 certificate carried in the "x5t" field of the "req\_cnf" parameter. In fact, it is expected that C can typically specify its own authentication credential by reference, since AS is expected to obtain the actual authentication credential during a previous client registration process or secure association establishment with C.

~~~~~~~~~~~~~~~~~~~~~~~
   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience / 5 : "tempSensor4711",
     / scope /    9 : "read",
     / req_cnf /  4 : {
       e'x5t' : h'822E4879F2A41B510C1F9B'
     }
   }
~~~~~~~~~~~~~~~~~~~~~~~
{: #token-request title="Example of C-to-AS POST /token request for an access token."}

If C wants to update its access rights without changing an existing OSCORE Security Context, it MUST include EDHOC\_Information in its POST request to the /token endpoint. The EDHOC\_Information MUST include the "session\_id" field. This POST request MUST omit the "req_cnf" parameter. An example of such a request is shown in {{token-request-update}}.

The identifier "session\_id" is assigned by AS as discussed in {{token-series}}, and, together with other information such as audience (see {{Section 5.8.1 of RFC9200}}), can be used by AS to determine the token series to which the new requested access token has to be added. Therefore, the session\_id MUST identify the pair (AUTH\_CRED\_C, AUTH\_CRED\_RS) associated with a still valid access token previously issued for C and RS by AS.

AS MUST verify that the received "session\_id" identifies a token series to which a still valid access token issued for C and RS belongs. If that is not the case, the Client-to-AS request MUST be declined with the error code "invalid_request" as defined in {{Section 5.8.3 of RFC9200}}.

~~~~~~~~~~~~~~~~~~~~~~~
   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience /      5 : "tempSensor4711",
     / scope /         9 : "write",
     e'edhoc_info_param' : {
        e'session_id' : h'01'
     }
   }
~~~~~~~~~~~~~~~~~~~~~~~
{: #token-request-update title="Example of C-to-AS POST /token request for updating access rights to an access token."}

## Token Series {#token-series}

This document refers to "token series" as a series of access tokens sorted in chronological order as they are released, characterized by the following properties:

* issued by the same AS
* issued to the same C, and associated with the same authentication credential of C
* issued for the same RS, identified by the same authentication credential

Upon a successful update of access rights, the new issued access token becomes the latest in its token series. When the latest access token of a token series becomes invalid (e.g., due to its expiration or revocation), the token series it belongs to ends.

The general token series concept is defined in {{I-D.ietf-ace-workflow-and-params}}. In this profile, a token series is characterized by access tokens used between a given pair (C, RS) having the same "session\_id" in the EDHOC\_Information, see {{edhoc-parameters-object}}.

AS assigns the "session\_id" to the EDHOC\_Information when issuing the first access token of a new series and that "session\_id" remains fixed throughout the series lifetime. When assigning the identifier, AS MUST ensure that it was not used in a previous series whose access tokens share the following properties with the access tokens of the new series:

* i) issued for the same RS; and
* ii) bound to the same authentication credential AUTH_CRED_C of the requesting client (irrespectively of how the AUTH_CRED_C is identified in the access tokens).

In case the access token is issued for a group-audience (see {{Section 6.9 of RFC9200}}), what is defined above applies, with the difference that the token series is associated with all the RSs in the group-audience, as indicated by their respective AUTH_CRED_RS.

## AS-to-C: Response # {#as-c}

After verifying the POST request to the /token endpoint and that C is authorized to access, AS responds as defined in {{Section 5.8.2 of RFC9200}}, with potential modifications as detailed below. If the request from C was invalid, or not authorized, AS returns an error response as described in {{Section 5.8.3 of RFC9200}}.

AS can signal that the use of EDHOC and OSCORE as per this profile is REQUIRED for a specific access token, by including the "ace_profile" parameter with the value "coap_edhoc_oscore" in the access token response. This means that C MUST use EDHOC with RS and derive an OSCORE Security Context, as specified in {{edhoc-exec}}. After that, C MUST use the established OSCORE Security Context to protect communications with RS, when accessing protected resources at RS according to the authorization information indicated in the access token. Usually, it is assumed that constrained devices will be pre-configured with the necessary profile, so that this kind of profile signaling can be omitted.

 According to this document, the AS provides the access token to C, by specifying it in the "access\_token" parameter of the access token response. An alternative workflow where the access token is uploaded by AS directly to RS is described in {{I-D.ietf-ace-workflow-and-params}}.

When issuing any access token, AS MUST send the following data in the response to C.

* The "session\_id" field of EDHOC\_Information, which is the identifier of the token series which the issued access token belongs to.

When issuing the first access token of a token series, AS MUST send the following data in the response to C.

* A unique identification of the authentication credential of RS, AUTH\_CRED\_RS. This is specified in the "rs\_cnf" parameter defined in {{RFC9201}}. AUTH\_CRED\_RS can be transported by value or referred to by means of an appropriate identifier.

   When issuing the first access token ever to a pair (C, RS) using a pair of corresponding authentication credentials (AUTH\_CRED\_C, AUTH\_CRED\_RS), it is typically expected that the response to C may include AUTH\_CRED\_RS by value.

   When later issuing further access tokens to the same pair (C, RS) using the same AUTH\_CRED\_RS, it is expected that the response to C includes AUTH\_CRED\_RS by reference.

When issuing the first access token of a token series, AS MAY send EDHOC\_Information related to RS, see {{edhoc-parameters-object}}, in corresponding fields of the response to C. This information is based on knowledge that AS have about RS, e.g., from a previous onboarding process, with particular reference to what RS supports as EDHOC peer.

{{fig-token-response}} shows an example of an AS response. The "rs_cnf" parameter specifies the authentication credential of RS, as an X.509 certificate transported by value in the "x5chain" field. The access token and the authentication credential of RS have been truncated for readability.

~~~~~~~~~~~~~~~~~~~~~~~
   Header: Created (Code=2.01)
      Content-Format: application/ace+cbor
      Payload:
      {
        / access_token / 1 : h'8343a1010aa2044c53/...
          (remainder of access token (CWT) omitted for brevity)/',
        / ace_profile / 38 : e'coap_edhoc_oscore',
        / expires_in /   2 : 3600,
        / rs_cnf /      41 : {
          e'x5chain' : h'3081ee3081a1a00302/...'
            (remainder of the credential omitted for brevity)/'
        }
        e'edhoc_info_param' : {
          e'session_id'    : h'01',
          e'methods'       : [0, 1, 2, 3],
          e'cipher_suites' : 0
        }
      }
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-token-response title="Example of AS-to-C Access Token response with EDHOC and OSCORE profile."}

### Access Token

When issuing any access token of a token series, AS MUST specify the following data in the claims associated with the access token.

* The "session\_id" field of EDHOC\_Information, with the same value specified in the response to C from the /token endpoint.

* The authentication credential that C specified in its POST request to the /token endpoint (see {{c-as}}), AUTH\_CRED\_C. If the access token is a CWT, this information MUST be specified in the "cnf" claim.

   In the access token, AUTH\_CRED\_C can be transported by value or uniquely referred to by means of an appropriate identifier, regardless of how C specified it in the request to the /token endpoint. Thus, the specific field carried in the access token claim and specifying AUTH\_CRED\_C depends on the specific way used by AS.

   When issuing the first access token ever to a pair (C, RS) using a pair of corresponding authentication credentials (AUTH\_CRED\_C, AUTH\_CRED\_RS), it is typically expected that AUTH\_CRED\_C is included by value.

   When later issuing further access tokens to the same pair (C, RS) using the same AUTH\_CRED\_C, it is expected that AUTH\_CRED\_C is identified by reference.

When issuing the first access token of a token series, AS MAY specify the following EDHOC\_Information (see {{edhoc-parameters-object}}) in the claims associated with the access token. If these data are specified in the response to C from the /token endpoint, they MUST be included with the same values in the access token.

* osc\_ms\_len: The size of the OSCORE Master Secret. If it is not included, the default value from {{Section A.1 of RFC9528}} is assumed.

* osc\_salt\_len: The size of the OSCORE Master Salt. If it is not included, the default value from {{Section A.1 of RFC9528}} is assumed.

* osc\_version: The OSCORE version. If it is not included, the default value of 1 (see {{Section 5.4 of RFC8613}}) is assumed.

To avoid the complexity of different encodings, an access token of this profile SHALL be a CBOR Web Token (CWT), see {{RFC8392}}. EDHOC\_Information MUST be transported in the "edhoc\_info" claim, defined in {{iana-token-cwt-claims}}.

The access token needs to be protected for various reasons. To prevent manipulation of the content, it needs to be integrity protected. RS needs to be able to verify that the access token is issued by a trusted AS (source authentication). Depending on use case and deployment, the access token may need to be confidentiality protected, for example, for privacy reasons.

AS can protect the access token by different means as discussed in {{Section 6.1 of RFC9200}}. It is RECOMMENDED that a COSE method is used as specified in {{RFC8392}}. Depending on audience there may be different ways to most appropriately confidentiality protected the access token. For a single RS, the CWT may be wrapped in COSE_Encrypt / COSE_Encrypt0, but if it needs to be read by multiple RSs then confidentiality protection may be better applied during transport, e.g., using EDHOC EAD_3 from C to RS.

{{fig-token}} shows an example CWT Claims Set, including the relevant EDHOC parameters in the "edhoc\_info" claim. The "cnf" claim specifies the authentication credential of C, as an X.509 certificate transported by value in the "x5chain" field. The authentication credential of C has been truncated for readability.

~~~~~~~~~~~~~~~~~~~~~~~
   {
    / aud /   3 : "tempSensorInLivingRoom",
    / iat /   6 : 1563451500,
    / exp /   4 : 1563453000,
    / scope / 9 :  "temperature_g firmware_p",
    / cnf /   8 : {
      e'x5chain' : h'3081ee3081a1a00302/...
        (remainder of the credential omitted for brevity)/'
    }
    e'edhoc_info_claim' : {
      e'session_id'    : h'01',
      e'methods'       : [0, 1, 2, 3],
      e'cipher_suites' : 0
    }
  }
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-token title="Example of CWT Claims Set with EDHOC parameters."}

### Processing in C

When receiving an Access Token response including the "rs\_cnf" parameter, C checks whether it is already storing the authentication credential of RS, namely AUTH\_CRED\_RS, specified in "rs\_cnf" by value or reference.

If this is not the case, C retrieves AUTH\_CRED\_RS, either using the "rs_cnf" parameter or some other trusted source. After that, C validates the actual AUTH\_CRED\_RS. In case of successful validation, C stores AUTH\_CRED\_RS as a valid authentication credential. Otherwise, C MUST delete the access token.

### Update of Access Rights

If C has a valid OSCORE Security Context associated to a valid access token, then C can send a request to AS for updating of its access rights.

If the request is granted then AS generates a new access token, where the "edhoc\_info" claim MUST include only the "session\_id" field. The access token is provisioned to RS either via C as specified in this document, or directly as described in {{I-D.ietf-ace-workflow-and-params}}. In either case, AS responds to C such that:

* The response MUST NOT include the "rs\_cnf" parameter.

* The EDHOC\_Information in the response MUST include only the "session\_id" field.

The "session\_id" needs to be included in the new access token in order for RS to identify the old access token to supersede, as well as the OSCORE Security Context already shared between C and RS and to be associated with the new access token.

## EDHOC_Information # {#edhoc-parameters-object}

Editor's note: Remove the JSON option

EDHOC\_Information is an object including information that guides two peers towards executing the EDHOC protocol. In particular, the EDHOC\_Information is defined to be serialized and transported between nodes, as specified by this document, but it can also be used by other specifications if needed.

The EDHOC\_Information can be encoded either as a JSON object or as a CBOR map. The set of common fields that can appear in an EDHOC\_Information can be found in the IANA "EDHOC Information" registry (see {{iana-edhoc-parameters}}), defined for extensibility, and the initial set of parameters defined in this document is specified below. All parameters are optional.

{{table-cbor-key-edhoc-params}} provides a summary of the EDHOC\_Information parameters defined in this section.

| Name          | CBOR label | CBOR type            | Registry                                       | Description                                                               |
| session_id    | 0          | bstr                 |                                                | Identifier of a session                                                   |
| methods       | 1          | int or array         | EDHOC Method Type Registry                     | Set of supported EDHOC methods                                            |
| cipher_suites | 2          | int or array         | EDHOC Cipher Suites Registry                   | Set of supported EDHOC cipher suites                                      |
| message_4     | 3          | True or False        |                                                | Support for EDHOC message_4                                               |
| comb_req      | 4          | True or False        |                                                | Support for the EDHOC + OSCORE combined request                           |
| uri_path      | 5          | tstr                 |                                                | URI-path of the EDHOC resource                                            |
| osc_ms_len    | 6          | uint                 |                                                | Length in bytes of the OSCORE Master Secret to derive                     |
| osc_salt_len  | 7          | uint                 |                                                | Length in bytes of the OSCORE Master Salt to derive                       |
| osc_version   | 8          | uint                 |                                                | OSCORE version number to use                                              |
| cred_types    | 9          | int or array         | EDHOC Authentication Credential Types Registry | Set of supported types of authentication credentials for EDHOC            |
| id_cred_types | 10         | int or tstr or array | COSE Header Parameters Registry                | Set of supported types of authentication credential identifiers for EDHOC |
| eads          | 11         | uint or array        | EDHOC External Authorization Data Registry     | Set of supported EDHOC External Authorization Data (EAD) items            |
| initiator     | 12         | True or False        |                                                | Support for the EDHOC Initiator role                                      |
| responder     | 13         | True or False        |                                                | Support for the EDHOC Responder role                                      |
{: #table-cbor-key-edhoc-params title="EDHOC_Information Parameters" align="center"}

* session\_id: This parameter identifies a 'session' which the EDHOC information is associated with, but does not necessarily identify a specific EDHOC session. In this document, "session\_id" identifies a token series. In JSON, the "session\_id" value is a Base64 encoded byte string. In CBOR, the "session\_id" type is a byte string, and has label 0.

* methods: This parameter specifies a set of supported EDHOC methods (see {{Section 3.2 of RFC9528}}). If the set is composed of a single EDHOC method, this is encoded as an integer. Otherwise, the set is encoded as an array of integers, where each array element encodes one EDHOC method. In JSON, the "methods" value is an integer or an array of integers. In CBOR, the "methods" is an integer or an array of integers, and has label 1.

* cipher\_suites: This parameter specifies a set of supported EDHOC cipher suites (see {{Section 3.6 of RFC9528}}). If the set is composed of a single EDHOC cipher suite, this is encoded as an integer. Otherwise, the set is encoded as an array of integers, where each array element encodes one EDHOC cipher suite. In JSON, the "cipher\_suites" value is an integer or an array of integers. In CBOR, the "cipher\_suites" is an integer or an array of integers, and has label 2.

* message\_4: This parameter indicates whether the EDHOC message\_4 (see {{Section 5.5 of RFC9528}}) is supported. In JSON, the "message\_4" value is a boolean. In CBOR, "message\_4" is the simple value "true" or "false", and has label 4.

* comb\_req: This parameter indicates whether the combined EDHOC + OSCORE request defined in {{I-D.ietf-core-oscore-edhoc}}) is supported. In JSON, the "comb\_req" value is a boolean. In CBOR, "comb\_req" is the simple value "true" or "false", and has label 5.

* uri\_path: This parameter specifies the path component of the URI of the EDHOC resource where EDHOC messages have to be sent as requests. In JSON, the "uri\_path" value is a string. In CBOR, "uri\_path" is a text string, and has label 6.

* osc\_ms\_len: This parameter specifies the size in bytes of the OSCORE Master Secret to derive after the EDHOC session, as per {{Section A.1 of RFC9528}}. In JSON, the "osc\_ms\_len" value is an integer. In CBOR, the "osc\_ms\_len" type is unsigned integer, and has label 7.

* osc\_salt\_len: This parameter specifies the size in bytes of the OSCORE Master Salt to derive after the EDHOC session, as per {{Section A.1 of RFC9528}}. In JSON, the "osc\_salt\_len" value is an integer. In CBOR, the "osc\_salt\_len" type is unsigned integer, and has label 8.

* osc\_version: This parameter specifies the OSCORE Version number that the two EDHOC peers have to use when using OSCORE. For more information about this parameter, see {{Section 5.4 of RFC8613}}. In JSON, the "osc\_version" value is an integer. In CBOR, the "osc\_version" type is unsigned integer, and has label 9.

* cred\_types: This parameter specifies a set of supported types of authentication credentials for EDHOC (see {{Section 3.5.2 of RFC9528}}). If the set is composed of a single type of authentication credential, this is encoded as an integer. Otherwise, the set is encoded as an array of integers, where each array element encodes one type of authentication credential. In JSON, the "cred\_types" value is an integer or an array of integers. In CBOR, "cred\_types" is an integer or an array of integers, and has label 9. The integer values are taken from the "EDHOC Authentication Credential Types" registry defined in {{I-D.ietf-core-oscore-edhoc}}.

* id\_cred\_types: This parameter specifies a set of supported types of authentication credential identifiers for EDHOC (see {{Section 3.5.3 of RFC9528}}). If the set is composed of a single type of authentication credential identifier, this is encoded as an integer or a text string. Otherwise, the set is encoded as an array, where each array element encodes one type of authentication credential identifier, as an integer or a text string. In JSON, the "id\_cred\_types" value is an integer, or a text string, or an array of integers and text strings. In CBOR, "id\_cred\_types" is an integer or a text string, or an array of integers and text strings, and has label 10. The integer or text string values are taken from the 'Label' column of the "COSE Header Parameters" registry {{COSE.Header.Parameters}}.

* eads: This parameter specifies a set of supported EDHOC External Authorization Data (EAD) items, identified by their ead\_label (see {{Section 3.8 of RFC9528}}). If the set is composed of a single ead\_label, this is encoded as an unsigned integer. Otherwise, the set is encoded as an array of unsigned integers, where each array element encodes one ead\_label. In JSON, the "eads" value is an unsigned integer or an array of unsigned integers. In CBOR, "eads" is an unsigned integer or an array of unsigned integers, and has label 11. The unsigned integer values are taken from the 'Label' column of the "EDHOC External Authorization Data" registry defined in {{RFC9528}}.

* initiator: This parameter specifies whether the EDHOC Initiator role is supported. In JSON, the "initiator" value is a boolean. In CBOR, "initiator" is the simple value "true" (0xf5) or "false" (0xf4), and has label 12.

* responder: This parameter specifies whether the EDHOC Responder role is supported. In JSON, the "responder" value is a boolean. In CBOR, "responder" is the simple value "true" (0xf5) or "false" (0xf4), and has label 13.

An example of JSON EDHOC\_Information is given in {{fig-edhoc-info-json}}.

~~~~~~~~~~~
   "edhoc_info" : {
       "session_id"    : b64'AQ==',
       "methods"       : 1,
       "cipher_suites" : 0
   }
~~~~~~~~~~~
{: #fig-edhoc-info-json title="Example of JSON EDHOC_Information"}

The CDDL grammar describing the CBOR EDHOC_Information is:

~~~~~~~~~~~
EDHOC_Information = {
  ?  0 => bstr,                   ; id
  ?  1 => int / array,            ; methods
  ?  2 => int / array,            ; cipher_suites
  ?  3 => true / false,           ; message_4
  ?  4 => true / false,           ; comb_req
  ?  5 => tstr,                   ; uri_path
  ?  6 => uint,                   ; osc_ms_len
  ?  7 => uint,                   ; osc_salt_len
  ?  8 => uint,                   ; osc_version
  ?  9 => int / array,            ; cred_types
  ? 10 => int / tstr / array,     ; id_cred_types
  ? 11 => uint / array,           ; eads
  ? 12 => true / false,           ; initiator
  ? 13 => true / false,           ; responder
  * int / tstr => any
}
~~~~~~~~~~~


# Client-RS Communication # {#c-rs-comm}

This section describes the exchange between C and RS, including the token uploading to RS, and the execution of the EDHOC protocol. The alternative workflow where AS uploads the access token directly to RS is described in {{I-D.ietf-ace-workflow-and-params}}.

The case where C sends a POST request to the /authz-info endpoint at RS is detailed in {{c-rs}} and {{rs-c}}, and shown by the example in {{example-without-optimization}}.

The case where C uploads the access token in an EAD field of an EDHOC message while executing the EDHOC protocol with RS is discussed in {{AT-in-EAD}} and {{edhoc-exec}}, and shown by the example in {{example-with-optimization}}.

In either case, C and RS run the EDHOC protocol by exchanging POST requests and related responses to a dedicated EDHOC resource at RS (see {{edhoc-exec}}). Once completed the EDHOC session, C and RS have agreed on a common secret key PRK\_out (see {{Section 4.1.3 of RFC9528}}), from which they establish an OSCORE Security Context (see {{edhoc-exec}}). After that, C and RS use the established OSCORE Security Context to protect their communications when accessing protected resources at RS, as per the access rights specified in the access token (see {{access-rights-verif}}).

C and RS are mutually authenticated once they have successfully completed the EDHOC protocol. RS gets key confirmation of PRK\_out by C at the end of the successful EDHOC session. Conversely, C get key confirmation of PRK\_out by RS either when receiving and successfully verifying the optional EDHOC message\_4 from RS, or when successfully verifying a response from RS protected with the generated OSCORE Security Context.

## C-to-RS: POST to /authz-info endpoint # {#c-rs}

The access token can be uploaded to RS using CoAP {{RFC7252}} and the Authorization Information endpoint as described in {{Section 5.10.1 of RFC9200}}.

That is, C sends a POST request to the /authz-info endpoint at RS, with the request payload conveying the access token without any CBOR wrapping. As per {{Section 5.10.1 of RFC9200}}, the Content-Format of the POST request has to reflect the format of the transported access token. In particular, if the access token is a CWT, the Content-Format MUST be "application/cwt".

The communication with the /authz-info endpoint is in general not protected, except in the case of updating the access rights (see {{update-access-rights-c-rs}}).

##  RS-to-C: 2.01 (Created) {#rs-c}

Upon receiving an access token from C, RS MUST follow the procedures defined in {{Section 5.10.1 of RFC9200}}. That is, RS must verify the validity of the access token. RS may make an introspection request (see {{Section 5.9.1 of RFC9200}}) to validate the access token.

If the access token is valid, RS proceeds as follows.

RS checks whether it is already storing the authentication credential of C, AUTH_CRED_C, specified in the "cnf" claim of the access token by value or by reference. If not, RS retrieves AUTH_CRED_C, either using the "cnf" claim or some other trusted source.

If RS fails to find or validate AUTH_CRED_C, then RS MUST respond with an error response code equivalent to the CoAP code 4.00 (Bad Request). RS may provide additional information in the payload of the error response, in order to clarify what went wrong.

If, instead, the access token is valid but associated with claims that RS cannot process (e.g., an unknown scope), or if any of the expected parameters is missing (e.g., any of the mandatory parameters from AS or the identifier "session\_id"), or if any parameters received in the EDHOC_Information is unrecognized, then RS MUST respond with an error response code equivalent to the CoAP code 4.00 (Bad Request). In the latter two cases, RS may provide additional information in the payload of the error response, in order to clarify what went wrong.

If all validations are successful, RS MUST reply to the POST request with a 2.01 (Created) response. The access token is stored such that it is possible to retrieve it based on "session\_id" and AUTH_CRED_C.

When an access token becomes invalid (e.g., due to its expiration or revocation), RS MUST delete the access token and the associated OSCORE Security Context, and MUST notify C with an error response with code 4.01 (Unauthorized) for any long running request, as specified in {{Section 5.8.3 of RFC9200}}.

## Access Token in External Authorization Data {#AT-in-EAD}

Instead of uploading the access token to the /authz-info endpoint at RS as described in {{c-rs}}, C MAY include the access token in EDHOC message\_3 by making use of the External Authorization Data field EAD_3 (see {{Section 3.8 of RFC9528}}), see example in {{example-with-optimization}}. In this case, the access token is encrypted between C and RS enabling protection of potential sensitive information.

This document defines the EAD item EAD\_ACCESS\_TOKEN = (ead\_label, ead\_value), where:

* ead\_label is the integer value TBD registered in {{iana-edhoc-ead}} and
* ead\_value is a CBOR byte string, with value the binary serialization of a CBOR map. The CBOR map includes one field, whose label is a CBOR unsigned integer with value either 0 or 1, and whose value is a CBOR byte string:

   * For label 0, ead\_value = { 0 : access\_token }, where access_token is a CBOR byte string equal to the value of the "access\_token" field of the access token response from AS, see {{as-c}}.
   * For label 1, ead\_value = { 1 : session\_id }, where session_id is a CBOR byte string equal to the value of the "session\_id" field of the access token response from AS, see {{token-series}}.

This EAD item, which is used in EAD\_3, is critical, i.e., it is used only with the negative value of its ead\_label, indicating that the receiving RS must either process the access token or abort the EDHOC session (see {{Section 3.8 of RFC9528}}). A Client or Resource Server supporting the profile of ACE defined in this document MUST support this EAD item. When EDHOC is used with this profile, this EAD item is included in EAD_3, see {{m_3}}.

Access tokens are transported in EAD fields only for the first access token of a token series, and not for the update of access rights, see {{update-access-rights-c-rs}}.

## EDHOC Session and OSCORE Security Context # {#edhoc-exec}

In order to mutually authenticate and establish secure communication for authorized access according to the profile described in this document, C and RS run the EDHOC protocol {{RFC9528}} with C as EDHOC Initiator and RS as EDHOC Responder. When a new EDHOC session is established, previous EDHOC sessions associated with the same access token and the same pair (session_id, AUTH_CRED_C) are deleted, see {{m_3}}. The OSCORE Security Contexts derived from those EDHOC sessions are also deleted.

As per {{Section A.2 of RFC9528}}, C sends EDHOC message\_1 and EDHOC message\_3 to an EDHOC resource at RS, as CoAP POST requests. RS sends EDHOC message\_2 and (optionally) EDHOC message\_4 as 2.04 (Changed) CoAP responses. C MUST target the EDHOC resource at RS with the URI path specified in the "uri_path" field of the EDHOC\_Information in the access token response received from AS (see {{c-as}}), if present.

In order to seamlessly run EDHOC, a client does not have to first upload to RS an access token whose scope explicitly indicates authorized access to the EDHOC resource. At the same time, RS has to ensure that attackers cannot perform requests on the EDHOC resource, other than sending EDHOC messages. Specifically, it SHOULD NOT be possible to perform anything else than POST on an EDHOC resource.

### EDHOC message\_1

The processing of EDHOC message\_1 is specified in {{Section 5.2 of RFC9528}}. Additionally, the following applies:

* The EDHOC method MUST be one of the EDHOC methods specified in the "methods" field (if present) in the EDHOC\_Information of the access token response to C.

* The selected cipher suite MUST be an EDHOC cipher suite specified in the "cipher\_suites" field (if present) in the EDHOC\_Information of the access token response to C.

### EDHOC message\_2

The processing of EDHOC message\_2 is specified in {{Section 5.3 of RFC9528}} with the following additions:

* The authentication credential CRED\_R indicated by the message field ID\_CRED\_R is AUTH\_CRED\_RS.

### EDHOC message\_3 {#m_3}

The processing of EDHOC message\_3 is specified in {{Section 5.4 of RFC9528}} with the following additions:

* The authentication credential CRED\_I indicated by the message field ID\_CRED\_I is AUTH\_CRED\_C.

* The EAD item EAD\_ACCESS\_TOKEN = (-ead\_label, ead\_value) MUST be included in the EAD\_3 field. If the access token is provisioned with EDHOC message\_3 as specified in {{AT-in-EAD}}, then ead\_value = { 0 : access\_token}, otherwise ead\_value = { 1 : session\_id}, where session\_id is equal to the value of the "session_id" field of the access token response from AS, see {{token-series}}.

* The RS MUST ensure that the access token is valid, potentially first retrieving it using session\_id and AUTH\_CRED\_C, the validation follows the procedure specified in {{rs-c}}. If such a process fails, RS MUST reply to C with an EDHOC error message with ERR\_CODE = 1 (see {{Section 6 of RFC9528}}), and it MUST abort the EDHOC session. RS MUST have successfully validated the processing of the access token before completing the EDHOC session. If completed successfully, then the EDHOC session is associated with both the access token and the pair (session_id, AUTH_CRED_C). Any old existing EDHOC session associated with the same access token and with the same pair (session_id, AUTH_CRED_C) MUST be deleted, together with the OSCORE Security Context derived from the EDHOC session.

Editor's note: Instead of ERR\_CODE = 1, consider to use ERR\_CODE = 3 "Access Denied"  defined in draft-ietf-lake-authz

### OSCORE Security Context

Once successfully completed the EDHOC session, C and RS derive an OSCORE Security Context, as defined in {{Section A.1 of RFC9528}}. In addition, the following applies.

* The length in bytes of the OSCORE Master Secret (i.e., the oscore\_key\_length parameter, see {{Section A.1 of RFC9528}}) MUST be the value specified in the "osc\_ms\_size" field (if present) in the EDHOC\_Information of the access token response to C, and of the access token provisioned to RS, respectively.

* The length in bytes of the OSCORE Master Salt (i.e., the oscore\_salt\_length parameter, see {{Section A.1 of RFC9528}}) MUST be the value specified in the "osc\_salt\_size" field (if present) in the EDHOC\_Information of the access token response to C, and of the access token provisioned to RS, respectively.

* C and RS MUST use the OSCORE version specified in the "osc\_version" field (if present) in the EDHOC\_Information of the access token response to C, and of the access token provisioned to RS, respectively.

* RS associates the latest EDHOC session and the derived OSCORE Security Context
with the stored access token, which is bound to the authentication credential (AUTH_CRED_C = CRED_I) used in the EDHOC session and with the session_id identifying the token series to which the access token belongs.

If supported by C, C MAY use the EDHOC + OSCORE combined request defined in {{I-D.ietf-core-oscore-edhoc}}, unless the "comb\_req" field of the EDHOC\_Information was present in the access token response and set to the CBOR simple value "false" (0xf4). In the combined request, both EDHOC message\_3 and the first OSCORE-protected application request are combined together in a single OSCORE-protected CoAP request, thus saving one round trip. For an example, see {{example-with-optimization}}. This requires C to derive the OSCORE Security Context with RS already after having successfully processed the received EDHOC message\_2 and before sending EDHOC message\_3.

## Update of Access Rights {#update-access-rights-c-rs}

Editor's note: This section should allow for access rights being updated by AS posting to RS.

If C has already established access rights and an OSCORE Security Context with RS, then C can update its access rights by posting a new access token to the /authz-info endpoint.

The new access token contains the updated access rights for C to access protected resources at RS, and C has to obtain it from AS as a new access token in the same token series of the current one (see {{c-as-comm}}). When posting the new access token to the /authz-info endpoint, C MUST protect the POST request using the current OSCORE Security Context shared with RS. After successful verification (see {{rs-c}}), RS will replace the old access token with the new one, while preserving the same OSCORE Security Context. In particular, C and RS do not re-run the EDHOC protocol and they do not establish a new OSCORE Security Context.

Editor's note: Mention the alternative when the AS uploads the new access token to RS.

If RS receives an access token in an OSCORE protected request, it means that C is requesting an update of access rights. In this case, RS MUST check the following conditions:

* RS checks whether it stores an access token T_OLD, such that the "session\_id" field of EDHOC_Information matches the "session\_id" field of EDHOC_Information in the new access token T_NEW.

* RS checks whether the OSCORE Security Context CTX used to protect the request matches the OSCORE Security Context associated with the stored access token T_OLD.

If both the conditions above hold, RS MUST replace the old access token T_OLD with the new access token T_NEW, and associate T_NEW with the OSCORE Security Context CTX. Then, RS MUST respond with a 2.01 (Created) response protected with the same OSCORE Security Context, with no payload.

Otherwise, RS MUST respond with a 4.01 (Unauthorized) error response. RS may provide additional information in the payload of the error response, in order to clarify what went wrong.

As specified in {{Section 5.10.1 of RFC9200}}, when receiving an updated access token with updated authorization information from C (see {{c-rs}}), it is recommended that RS overwrites the previous access token. That is, only the latest authorization information in the access token received by RS is valid. This simplifies the process needed by RS to keep track of authorization information for a given client.

## Discarding the Security Context # {#discard-context}

There are a number of cases where C or RS have to discard the OSCORE Security Context, and possibly establish a new one.

C MUST discard the current OSCORE Security Context shared with RS when any of the following occurs.

* The OSCORE Sender Sequence Number space of C is exhausted.

* The access token associated with the OSCORE Security Context becomes invalid, for example due to expiration or revocation.

* C receives a number of unprotected 4.01 (Unauthorized) responses to OSCORE-protected requests, which are sent to RS and protected using the same OSCORE Security Context. The exact number of such received responses needs to be specified by the application. This may for example happen due to lack of storage in RS, which then sends the "AS Request Creation Hints" message (see {{Section 5.3 of RFC9200}}).

* The authentication credential of C (of RS) becomes invalid, e.g., due to expiration or revocation, and it was used as CRED\_I (CRED\_R) in the EDHOC session to establish the OSCORE Security Context.

RS MUST discard the current OSCORE Security Context shared with C when any of the following occurs:

* The OSCORE Sender Sequence Number space of RS is exhausted.

* The access token associated with the OSCORE Security Context becomes invalid, for example due to expiration or revocation.

* The authentication credential of C (of RS) becomes invalid (e.g., due to expiration or revocation), and it was used as CRED\_I (CRED\_R) in the EDHOC session to establish the OSCORE Security Context.

After a new access token is successfully uploaded to RS, and a new OSCORE Security Context is established between C and RS, messages still in transit that were protected with the previous OSCORE Security Context might not be successfully verified by the recipient, since the old OSCORE Security Context might have been discarded. This means that messages sent shortly before C has uploaded the new access token to RS might not be successfully accepted by the recipient.

Furthermore, implementations may want to cancel CoAP observations at RS, if registered before the new OSCORE Security Context has been established. Alternatively, applications need to implement a mechanism to ensure that, from then on, messages exchanged within those observations are going to be protected with the newly derived OSCORE Security Context.


## Cases of Establishing a New OSCORE Security Context

The procedure of provisioning a new access token to RS specified in this section applies to various cases when an OSCORE Security Context shared between C and RS has been deleted, for example as described in {{discard-context}}.

Another exceptional case is when there is still a valid OSCORE Security Context but it needs to be updated, e.g., due to a policy limiting its use in terms of time or amount of processed data, or to the imminent exhaustion of the OSCORE Sender Sequence Number space. In this case, C and RS SHALL attempt to run the KUDOS key update protocol {{I-D.ietf-core-oscore-key-update}}, which is a lightweight alternative independent of ACE and EDHOC that does not require the posting of an access token. If KUDOS is not supported, then C and RS falls back to EDHOC as outlined above.

In either case, C and RS establish a new OSCORE Security Context that replaces the old one and will be used for protecting their communications from then on. In particular, RS MUST associate the new OSCORE Security Context with the current (potentially re-posted) access token. Unless C and RS re-run the EDHOC protocol, they preserve their OSCORE identifiers, i.e., the OSCORE Sender/Recipient IDs.


## Access Rights Verification # {#access-rights-verif}

RS MUST follow the procedures defined in {{Section 5.10.2 of RFC9200}}. That is, if RS receives an OSCORE-protected request targeting a protected resource from C, then RS processes the request according to {{RFC8613}}, when Version 1 of OSCORE is used. Future specifications may define new versions of OSCORE, which AS can indicate C and RS to use by means of the "osc\_version" field of EDHOC\_Information (see {{c-as-comm}}).

If OSCORE verification succeeds and the target resource requires authorization, RS retrieves the authorization information using the access token associated with the OSCORE Security Context. Then, RS must verify that the authorization information covers the target resource and the action intended by C on it.


# Secure Communication with AS # {#secure-comm-as}

As specified in the ACE framework (see {{Sections 5.8 and 5.9 of RFC9200}}), the requesting entity (RS and/or C) and AS communicates via the /token or /introspect endpoint. When using this profile, the use of CoAP {{RFC7252}} and OSCORE {{RFC8613}} for this communication is RECOMMENDED. Other protocols fulfilling the security requirements defined in {{Section 5 of RFC9200}} (such as HTTP and DTLS {{RFC9147}} or TLS {{RFC8446}}) MAY be used instead.

If OSCORE is used, the requesting entity and AS need to have an OSCORE Security Context in place. While this can be pre-installed, the requesting entity and AS can establish such an OSCORE Security Context, for example, by running the EDHOC protocol, as shown between C and AS by the examples in {{example-without-optimization}} and {{example-with-optimization}}.

Furthermore, as discussed in {{as-c}}, AS may upload an access token directly to the /authz-info endpoint at RS. Unless encryption is applied, that exchange between AS and RS discloses the plain text token, just like when C uses the /authz-info endpoint at RS to upload a first token in a series.

Editor's note: Elaborate on how to encrypt the token from AS to RS, since there is a pre-established security context.

# CWT Confirmation Methods

This document defines a number of new CWT confirmation methods (see {{iana-cwt-confirmation-methods}}). The semantics of each confirmation method is defined below.

## Ordered Chain of X.509 Certificates # {#ssec-cwt-conf-x5chain}

The confirmation method "x5chain" specifies an ordered array of X.509 certificates {{RFC5280}}. The semantics of "x5chain" is like that of the "x5chain" COSE Header Parameter specified in {{RFC9360}}.

## Unordered Bag of X.509 Certificates # {#ssec-cwt-conf-x5bag}

The confirmation method "x5bag" specifies a bag of X.509 certificates {{RFC5280}}. The semantics of "x5bag" is like that of the "x5bag" COSE Header Parameter specified in {{RFC9360}}.

## Hash of an X.509 Certificate # {#ssec-cwt-conf-x5t}

The confirmation method "x5t" specifies the hash value of the end-entity X.509 certificate {{RFC5280}}. The semantics of "x5t" is like that of the "x5t" COSE Header Parameter specified in {{RFC9360}}.

## URI Pointing to an Ordered Chain of X.509 Certificates # {#ssec-cwt-conf-x5u}

The confirmation method "x5u" specifies the URI {{RFC3986}} of an ordered chain of X.509 certificates {{RFC5280}}. The semantics of "x5u" is like that of the "x5u" COSE Header Parameter specified in {{RFC9360}}.

## Ordered Chain of C509 Certificates # {#ssec-cwt-conf-c5c}

The confirmation method "c5c" specifies an ordered array of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5c" is like that of the "c5c" COSE Header Parameter specified in {{I-D.ietf-cose-cbor-encoded-cert}}.

## Unordered Bag of C509 Certificates # {#ssec-cwt-conf-c5b}

The confirmation method "c5b" specifies a bag of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5b" is like that of the "c5b" COSE Header Parameter specified in {{I-D.ietf-cose-cbor-encoded-cert}}.

## Hash of a C509 Certificate # {#ssec-cwt-conf-c5t}

The confirmation method "c5t" specifies the hash value of the end-entity C509 certificate {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5t" is like that of the "c5t" COSE Header Parameter specified in {{I-D.ietf-cose-cbor-encoded-cert}}.

## URI Pointing to an Ordered Chain of C509 Certificates # {#ssec-cwt-conf-c5u}

The confirmation method "c5u" specifies the URI {{RFC3986}} of a COSE_C509 containing an ordered chain of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. COSE_C509 is defined in {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5u" is like that of the "c5u" COSE Header Parameter specified in {{I-D.ietf-cose-cbor-encoded-cert}}.

## CWT Containing a COSE_Key # {#ssec-cwt-conf-kcwt}

The confirmation method "kcwt" specifies a CBOR Web Token (CWT) {{RFC8392}} containing a COSE_Key {{RFC9053}} in a 'cnf' claim and possibly other claims. The semantics of "kcwt" is like that of the "kcwt" COSE Header Parameter specified in {{RFC9528}}.

## CCS Containing a COSE_Key # {#ssec-cwt-conf-kccs}

The confirmation method "kccs" specifies a CWT Claims Set (CCS) {{RFC8392}} containing a COSE_Key {{RFC9053}} in a 'cnf' claim and possibly other claims. The semantics of "kccs" is like that of the "kccs" COSE Header Parameter specified in {{RFC9528}}.

# JWT Confirmation Methods

This document defines a number of new JWT confirmation methods (see {{iana-jwt-confirmation-methods}}). The semantics of each confirmation method is defined below.

## Ordered Chain of X.509 Certificates # {#ssec-jwt-conf-x5c}

The confirmation method "x5c" specifies an ordered array of X.509 certificates {{RFC5280}}. The semantics of "x5c" is like that of the "x5c" JSON Web Signature and Encryption Header Parameter specified in {{RFC7515}}, with the following difference. The public key contained in the first certificate is the proof-of-possession key and does not have to correspond to a key used to digitally sign the JWS.

## Unordered Bag of X.509 Certificates # {#ssec-jwt-conf-x5b}

The confirmation method "x5b" specifies a bag of X.509 certificates {{RFC5280}}. The semantics of the "x5b" is like that of the "x5c" JWT confirmation method defined in {{ssec-jwt-conf-x5c}}, with the following differences. First, the set of certificates is unordered and may contain self-signed certificates. Second, the composition and processing of "x5b" are like for the "x5bag" COSE Header Parameter defined in {{RFC9360}}.

## Hash of an X.509 Certificate # {#ssec-jwt-conf-x5t}

The confirmation method "x5t" specifies the hash value of the end-entity X.509 certificate {{RFC5280}}. The semantics of "x5t" is like that of the "x5t" JSON Web Signature and Encryption Header Parameter specified in {{RFC7515}}.

## URI Pointing to an Ordered Chain of X.509 Certificates # {#ssec-jwt-conf-x5u}

The confirmation method "x5u" specifies the URI {{RFC3986}} of an ordered chain of X.509 certificates {{RFC5280}}. The semantics of "x5u" is like that of the "x5u" COSE Header Parameter specified in {{RFC9360}}, with the following difference. The public key contained in the first certificate is the proof-of-possession key and does not have to correspond to a key used to digitally sign the JWS.

## Ordered Chain of C509 Certificates # {#ssec-jwt-conf-c5c}

The confirmation method "c5c" specifies an ordered array of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5c" is like that of the "x5c" JWT confirmation method defined in {{ssec-jwt-conf-x5c}}, with the following difference. Each string in the JSON array is a base64-encoded ({{Section 4 of RFC4648}} - not base64url-encoded) C509 certificate.

## Unordered Bag of C509 Certificates # {#ssec-jwt-conf-c5b}

The confirmation method "c5b" specifies a bag of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5b" is like that of the "c5c" JWT confirmation method defined in {{ssec-jwt-conf-c5c}}, with the following differences. First, the set of certificates is unordered and may contain self-signed certificates. Second, the composition and processing of "c5b" is like for the "c5b" COSE Header Parameter defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

## Hash of a C09 Certificate # {#ssec-jwt-conf-c5t}

The confirmation method "c5t" specifies the hash value of the end-entity C509 certificate {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5t" is like that of the "x5t" JWT confirmation method defined in {{ssec-jwt-conf-x5t}}, with the following differences. First, the base64url-encoded SHA-1 thumbprint is computed over the C509 certificate. Second, the public key contained in the C509 certificate does not have to correspond to a key used to digitally sign the JWS.

## URI Pointing to an Ordered Chain of C509 Certificates # {#ssec-jwt-conf-c5u}

The confirmation method "c5u" specifies the URI {{RFC3986}} of COSE_C509 containing an ordered chain of C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}. COSE_C509 is defined in {{I-D.ietf-cose-cbor-encoded-cert}}. The semantics of "c5u" is like that of the "x5u" JWT confirmation method defined in {{ssec-jwt-conf-x5u}}, with the following differences. First, the URI refers to a resource for the C509 certificate chain. Second, the public key contained in one of the C509 certificates and acting as proof-of-possession key does not have to correspond to a key used to digitally sign the JWS.

## CWT Containing a COSE_Key # {#ssec-jwt-conf-kcwt}

The confirmation method "kcwt" specifies a CBOR Web Token (CWT) {{RFC8392}} containing a COSE_Key {{RFC9053}} in a 'cnf' claim and possibly other claims. The format of "kcwt" is the base64url-encoded serialization of the CWT.

## CCS Containing a COSE_Key # {#ssec-jwt-conf-kccs}

The confirmation method "kccs" specifies a CWT Claims Set (CCS) {{RFC8392}} containing a COSE_Key {{RFC9053}} in a 'cnf' claim and possibly other claims. The format of "kcwt" is the base64url-encoded serialization of the CWT.

# Security Considerations

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}}. Thus, the general security considerations from the ACE framework also apply to this profile.

Furthermore, the security considerations from OSCORE {{RFC8613}} and from EDHOC {{RFC9528}} also apply to this specific use of the OSCORE and EDHOC protocols.

As previously stated, once completed the EDHOC session, C and RS are mutually authenticated through their respective authentication credentials, whose retrieval has been facilitated by AS. Also once completed the EDHOC session, C and RS have established a long-term secret key PRK\_out enjoying forward secrecy. This is in turn used by C and RS to establish an OSCORE Security Context.

Furthermore, RS achieves confirmation that C has PRK\_out (proof-of-possession) when completing the EDHOC session. Rather, C achieves confirmation that RS has PRK\_out (proof-of-possession) either when receiving the optional EDHOC message\_4 from RS, or when successfully verifying a response from RS protected with the established OSCORE Security Context.

OSCORE is designed to secure point-to-point communication, providing a secure binding between a request and the corresponding response(s). Thus, the basic OSCORE protocol is not intended for use in point-to-multipoint communication (e.g., enforced via multicast or a publish-subscribe model). Implementers of this profile should make sure that their use case of OSCORE corresponds to the expected one, in order to prevent weakening the security assurances provided by OSCORE.

When using this profile, it is RECOMMENDED that RS stores only one access token per client. The use of multiple access tokens for a single client increases the strain on RS, since it must consider every access token associated with the client and calculate the actual permissions that client has. Also, access tokens indicating different or disjoint permissions from each other may lead RS to enforce wrong permissions.  If one of the access tokens expires earlier than others, the resulting permissions may offer insufficient protection. Developers SHOULD avoid using multiple access tokens for a same client. Furthermore, RS MUST NOT store more than one access token per client per PoP-key (i.e., per client's authentication credential).

# Privacy Considerations

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}}. Thus, the general privacy considerations from the ACE framework also apply to this profile.

Furthermore, the privacy considerations from OSCORE {{RFC8613}} and from EDHOC {{RFC9528}} also apply to this specific use of the OSCORE and EDHOC protocols.

An unprotected response to an unauthorized request may disclose information about RS and/or its existing relationship with C. It is advisable to include as little information as possible in an unencrypted response. When an OSCORE Security Context already exists between C and RS, more detailed information may be included.

Except for the case where C attempts to update its access rights, the (encrypted) access token is sent in an unprotected POST request to the /authz-info endpoint at RS. Thus, if C uses the same single access token from multiple locations, it can risk being tracked by the access token's value even when the access token is encrypted.


The identifiers used in OSCORE, i.e., the OSCORE Sender/Recipient IDs, are negotiated by C and RS during the EDHOC session. That is, the EDHOC Connection Identifier C\_I of C is going to be the OSCORE Recipient ID of C (the OSCORE Sender ID of RS). Conversely, the EDHOC Connection Identifier C\_R of RS is going to be the OSCORE Recipient ID of RS (the OSCORE Sender ID of C). These OSCORE identifiers are privacy sensitive (see {{Section 12.8 of RFC8613}}). In particular, they could reveal information about C, or may be used for correlating different requests from C, e.g., across different networks that C has joined and left over time. This can be mitigated if C and RS dynamically update their OSCORE identifiers, e.g., by using the method defined in {{I-D.ietf-core-oscore-key-update}}.

# IANA Considerations

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with the RFC number of this specification and delete this paragraph.

## ACE Profiles Registry ## {#iana-ace-oauth-profile}

IANA is asked to add the following entry to the "ACE Profiles" registry, following the procedure specified in {{RFC9200}}.

* Name: coap_edhoc_oscore
* Description: Profile for delegating client authentication and authorization in a constrained environment by establishing an OSCORE Security Context {{RFC8613}} between resource-constrained nodes, through the execution of the lightweight authenticated key exchange protocol EDHOC {{RFC9528}}.
* CBOR Value:  TBD (value between 1 and 255)
* Reference:  {{&SELF}}

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entry to the "OAuth Parameters" registry.

* Name: "edhoc_info"
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-oauth-cbor-mappings}

IANA is asked to add the following entry to the "OAuth Parameters CBOR Mappings" registry, following the procedure specified in {{RFC9200}}.

* Name: "edhoc_info"
* CBOR Key: TBD
* Value Type: map
* Reference: {{&SELF}}

## JSON Web Token Claims Registry ## {#iana-token-json-claims}

IANA is asked to add the following entries to the "JSON Web Token Claims" registry, following the procedure specified in {{RFC7519}}.

*  Claim Name: "edhoc_info"
*  Claim Description: Information for EDHOC session
*  Change Controller: IETF
*  Reference: {{&SELF}}

## CBOR Web Token (CWT) Claims Registry ## {#iana-token-cwt-claims}

IANA is asked to add the following entries to the "CBOR Web Token (CWT) Claims" registry, following the procedure specified in {{RFC8392}}.

* Claim Name: "edhoc_info"
* Claim Description: Information for EDHOC session
* JWT Claim Name: "edhoc_info"
* Claim Key: TBD
* Claim Value Type: map
* Change Controller: IETF
* Reference: {{&SELF}}

## JWT Confirmation Methods Registry ## {#iana-jwt-confirmation-methods}

IANA is asked to add the following entries to the "JWT Confirmation Methods" registry, following the procedure specified in {{RFC7800}}.

* Confirmation Method Value: "x5c"
* Confirmation Method Description: An ordered chain of X.509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-x5c}} of {{&SELF}}

<br>

* Confirmation Method Value: "x5b"
* Confirmation Method Description: An unordered bag of X.509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-x5b}} of {{&SELF}}

<br>

* Confirmation Method Value: "x5t"
* Confirmation Method Description: Hash of an X.509 certificate
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-x5t}} of {{&SELF}}

<br>

* Confirmation Method Value: "x5u"
* Confirmation Method Description: URI pointing to an ordered chain of X.509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-x5u}} of {{&SELF}}

<br>

* Confirmation Method Value: "c5c"
* Confirmation Method Description: An ordered chain of C509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-c5c}} of {{&SELF}}

<br>

* Confirmation Method Value: "c5b"
* Confirmation Method Description: An unordered bag of C509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-c5b}} of {{&SELF}}

<br>

* Confirmation Method Value: "c5t"
* Confirmation Method Description: Hash of a C509 certificate
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-c5t}} of {{&SELF}}

<br>

* Confirmation Method Value: "c5u"
* Confirmation Method Description: URI pointing to a COSE_C509 containing an ordered chain of C509 certificates
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-c5u}} of {{&SELF}}

<br>

* Confirmation Method Value: "kcwt"
* Confirmation Method Description: A CBOR Web Token (CWT) containing a COSE_Key in a 'cnf' claim and possibly other claims
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-kcwt}} of {{&SELF}}

<br>

* Confirmation Method Value: "kccs"
* Confirmation Method Description: A CWT Claims Set (CCS) containing a COSE_Key in a 'cnf' claim and possibly other claims
* Change Controller: IETF
* Reference: {{ssec-jwt-conf-kccs}} of {{&SELF}}

## CWT Confirmation Methods Registry ## {#iana-cwt-confirmation-methods}

IANA is asked to add the following entries to the "CWT Confirmation Methods" registry, following the procedure specified in {{RFC8747}}.

* Confirmation Method Name: x5chain
* Confirmation Method Description: An ordered chain of X.509 certificates
* JWT Confirmation Method Name: "x5c"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_X509
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-x5chain}} of {{&SELF}}

<br>

* Confirmation Method Name: x5bag
* Confirmation Method Description: An unordered bag of X.509 certificates
* JWT Confirmation Method Name: "x5b"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_X509
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-x5bag}} of {{&SELF}}

<br>

* Confirmation Method Name: x5t
* Confirmation Method Description: Hash of an X.509 certificate
* JWT Confirmation Method Name: "x5t"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_CertHash
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-x5t}} of {{&SELF}}

<br>

* Confirmation Method Name: x5u
* Confirmation Method Description: URI pointing to an ordered chain of X.509 certificates
* JWT Confirmation Method Name: "x5u"
* Confirmation Key: TBD
* Confirmation Value Type: uri
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-x5u}} of {{&SELF}}

<br>

* Confirmation Method Name: c5c
* Confirmation Method Description: An ordered chain of C509 certificates
* JWT Confirmation Method Name: "c5c"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_C509
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-c5c}} of {{&SELF}}

<br>

* Confirmation Method Name: c5b
* Confirmation Method Description: An unordered bag of C509 certificates
* JWT Confirmation Method Name: "c5b"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_C509
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-c5b}} of {{&SELF}}

<br>

* Confirmation Method Name: c5t
* Confirmation Method Description: Hash of a C509 certificate
* JWT Confirmation Method Name: "c5t"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_CertHash
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-c5t}} of {{&SELF}}

<br>

* Confirmation Method Name: c5u
* Confirmation Method Description: URI pointing to a COSE_C509 containing an ordered chain of C509 certificates
* JWT Confirmation Method Name: "c5u"
* Confirmation Key: TBD
* Confirmation Value Type: uri
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-c5u}} of {{&SELF}}

<br>

* Confirmation Method Name: kcwt
* Confirmation Method Description: A CBOR Web Token (CWT) containing a COSE_Key in a 'cnf' claim and possibly other claims
* JWT Confirmation Method Name: "kcwt"
* Confirmation Key: TBD
* Confirmation Value Type: COSE_Messages
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-kcwt}} of {{&SELF}}

<br>

* Confirmation Method Name: kccs
* Confirmation Method Description: A CWT Claims Set (CCS) containing a COSE_Key in a 'cnf' claim and possibly other claims
* JWT Confirmation Method Name: "kccs"
* Confirmation Key: TBD
* Confirmation Value Type: map / #6(map)
* Change Controller: IETF
* Reference: {{ssec-cwt-conf-kccs}} of {{&SELF}}

## EDHOC External Authorization Data Registry # {#iana-edhoc-ead}

IANA is asked to add the following entry to the "EDHOC External Authorization Data" registry defined in {{Section 10.5 of RFC9528}}.

The ead\_label = TBD and the ead\_value define an access token transferred in an EAD item of EDHOC message\_3, with processing specified in {{AT-in-EAD}}.

* Name: ACE-OAuth Access Token
* Label: TBD
* Description: An Access Token as used in the ACE-OAuth framework {{RFC9200}}
* Reference: {{&SELF}}

## EDHOC Information Registry # {#iana-edhoc-parameters}

IANA is requested to create a new "EDHOC Information" registry within the "Ephemeral Diffie-Hellman Over COSE (EDHOC)" registry group defined in {{RFC9528}}.

As registration policy, the registry uses either "Standards Action with Expert Review", or "Specification Required" per {{Section 4.6 of RFC8126}}, or "Expert Review" per {{Section 4.5 of RFC8126}}. Expert Review guidelines are provided in {{iana-expert-review}}.

All assignments according to "Standards Action with Expert Review" are made on a "Standards Action" basis per {{Section 4.9 of RFC8126}}, with Expert Review additionally required per {{Section 4.5 of RFC8126}}. The procedure for early IANA allocation of Standards Track code points defined in {{RFC7120}} also applies. When such a procedure is used, review and approval by the designated expert are also required, in order for the WG chairs to determine that the conditions for early allocation are met (see step 2 in {{Section 3.1 of RFC7120}}).

The columns of the registry are:

* Name: A descriptive name that enables easier reference to this item. Because a core goal of this document is for the resulting representations to be compact, it is RECOMMENDED that the name be short.

   This name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts determine that there is a compelling reason to allow an exception. The name is not used in the CBOR encoding.

* CBOR label: The value to be used as CBOR abbreviation of the item.

   The value MUST be unique. The value can be a positive integer, a negative integer or a string. Integer values between -256 and 255 and strings of length 1 are designated as "Standards Action With Expert Review". Integer values from -65536 to -257 and from 256 to 65535 and strings of maximum length 2 are designated as "Specification Required". Integer values greater than 65535 and strings of length greater than 2 are designated as "Expert Review". Integer values less than -65536 are marked as "Private Use".

* CBOR type: The CBOR type of the item, or a pointer to the registry that defines its type, when that depends on another item.

* Registry: The registry that values of the item may come from, if one exists.

* Description: A brief description of this item.

* Specification: A pointer to the public specification for the item, if one exists.

This registry will be initially populated by the values in {{table-cbor-key-edhoc-params}}. In the "Specification" column, the value for all of these entries will be {{&SELF}} and {{RFC9528}}.

## Expert Review Instructions # {#iana-expert-review}

The IANA registry established in this document is defined as "Standards Action with Expert Review", "Specification Required", or "Expert Review", depending on the range of values for which an assignment is requested. This section gives some general guidelines for what the experts should be looking for, but they are being designated as experts for a reason so they should be given substantial latitude.

Expert reviewers should take into consideration the following points:

* Point squatting should be discouraged. Reviewers are encouraged to get sufficient information for registration requests to ensure that the usage is not going to duplicate one that is already registered and that the point is likely to be used in deployments. The zones tagged as private use are intended for testing purposes and closed environments; code points in other ranges should not be assigned for testing.

* Specifications are required for the Standards Action range of point assignment. Specifications should exist for Specification Required ranges, but early assignment before a specification is available is considered to be permissible. Specifications are needed for the first-come, first-serve range if they are expected to be used outside of closed environments in an interoperable way. When specifications are not provided, the description provided needs to have sufficient information to identify what the point is being used for.

* Experts should take into account the expected usage of fields when approving point assignment. The fact that there is a range for Standards Track documents does not mean that a Standards Track document cannot have points assigned outside of that range. The length of the encoded value should be weighed against how many code points of that length are left, the size of device it will be used on, and the number of code points left that encode to that size.

--- back

# Examples # {#examples}

This appendix provides examples where this profile of ACE is used. In particular:

* {{example-without-optimization}} does not make use of use of any optimization.

* {{example-with-optimization}} makes use of the optimizations defined in this specification, hence reducing the roundtrips of the interactions between the Client and the Resource Server.

All these examples build on the following assumptions, as relying on expected early procedures performed at AS. These include the registration of RSs by the respective Resource Owners as well as the registrations of Clients authorized to request access token for those RSs.

* AS knows the authentication credential AUTH_CRED_C of the Client C.

* The Client knows the authentication credential AUTH_CRED_AS of AS.

* AS knows the authentication credential AUTH_CRED_RS of RS.

* RS knows the authentication credential AUTH_CRED_AS of AS.

   This is relevant in case AS and RS actually require a secure association (e.g., for RS to perform token introspection at AS, or for AS to upload an access token to RS on behalf of the Client).

As a result of the assumptions above, it is possible to limit the transport of AUTH_CRED_C and AUTH_CRED_RS by value only to the following two cases, and only when the Client requests an access token for RS in question for the first time when considering the pair (AUTH_CRED_C, AUTH_CRED_RS).

* In the Token Response from AS to the Client, where AUTH_CRED_RS is specified by the 'rs_cnf' parameter.

* In the access token, where AUTH_CRED_C is specified by the 'cnf' claim.

Note that, even under the circumstances mentioned above, AUTH_CRED_C might rather be indicated by reference. This is possible if RS can effectively use such a reference from the access token to retrieve AUTH_CRED_C (e.g., from a trusted repository of authentication credentials reachable through a non-constrained link), and if AS is in turn aware of that.

In any other case, it is otherwise possible to indicate both AUTH_CRED_C and AUTH_CRED_RS by reference, when performing the ACE access control workflow as well as later on when the Client and RS run EDHOC.

## Workflow without Optimizations # {#example-without-optimization}

The example below considers the simplest (though least efficient) interaction between the Client and RS. That is: first C uploads the access token to RS; then C and RS run EDHOC; and, finally, the Client accesses the protected resource at RS.

~~~~~~~~~~~ aasvg
    C                                 AS                             RS
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
M03 |--------------------------------->|                              |
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M04 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     AUTH_CRED_C by reference     |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M05 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  'ace_profile' specifies the     |                              |
    |  ACE profile "coap_edhoc_oscore" |                              |
    |                                  |                              |
    |  'edhoc_info' specifies:         |                              |
    |     {                            |                              |
    |       e'session_id' : h'01',     |                              |
    |       e'cipher_suites' : 2,      |                              |
    |       e'methods' : 3             |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |  - the 'cnf' claim specifies     |                              |
    |    AUTH_CRED_C by value          |                              |
    |  - the 'edhoc_info' claim        |                              |
    |    specifies the same as         |                              |
    |    'edhoc_info' above            |                              |
    |                                  |                              |

     Possibly after chain verification, the Client adds AUTH_CRED_RS
     to the set of its trusted peer authentication credentials,
     relying on AS as trusted provider/

    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M06 |---------------------------------------------------------------->|
    |                                  |                              |

     Possibly after chain verification, RS adds AUTH_CRED_C
     to the set of its trusted peer authentication credentials,
     relying on AS as trusted provider/

    |                                  |                              |
    |   2.01 (Created)                 |                              |
    |   (unprotected message)          |                              |
M07 |<----------------------------------------------------------------|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M08 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M09 |<----------------------------------------------------------------|
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M10 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Access to protected resource    |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M11 |---------------------------------------------------------------->|
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M12 |<----------------------------------------------------------------|
    |                                  |                              |

     Later on, the access token expires ...
      - The Client and RS delete their OSCORE Security Context and
        purge the EDHOC session used to derive it (unless the same
        session is also used for other reasons).
      - RS retains AUTH_CRED_C as still valid,
        and AS knows about it.
      - The Client retains AUTH_CRED_RS as still valid,
        and AS knows about it.

    |                                  |                              |
    |                                  |                              |

     Time passes ...

    |                                  |                              |
    |                                  |                              |

     The Client asks for a new access token; now all the
     authentication credentials can be indicated by reference

     The price to pay is on AS, about remembering that at least
     one access token has been issued for the pair (Client, RS)
     and considering the pair (AUTH_CRED_C, AUTH_CRED_RS)

    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M13 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M14 |<---------------------------------|                              |
    |  'rs_cnf' identifies             |                              |
    |     AUTH_CRED_RS by reference    |                              |
    |                                  |                              |
    |  'ace_profile' specifies the     |                              |
    |  ACE profile "coap_edhoc_oscore" |                              |
    |                                  |                              |
    |  'edhoc_info' specifies:         |                              |
    |     {                            |                              |
    |       e'session_id' : h'05',     |                              |
    |       e'cipher_suites' : 2,      |                              |
    |       e'methods' : 3             |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |  - the 'cnf' claim specifies     |                              |
    |    AUTH_CRED_C by reference      |                              |
    |  - the 'edhoc_info' claim        |                              |
    |    specifies the same as         |                              |
    |    'edhoc_info' above            |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M15 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  2.01 (Created)                  |                              |
    |  (unprotected message)           |                              |
M16 |<----------------------------------------------------------------|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M17 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
    |  (no access control is enforced) |                              |
M18 |<----------------------------------------------------------------|
    |  ID_CRED_R specifies             |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M19 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M20 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M21 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~

## Workflow with Optimizations # {#example-with-optimization}

The example below builds on the example in {{example-without-optimization}}, while additionally relying on the two following optimizations.

* The access token is not separately uploaded to the /authz-info endpoint at RS, but rather included in the EAD\_3 field of EDHOC message\_3 sent by C to RS.

* The Client uses the EDHOC+OSCORE request defined in {{I-D.ietf-core-oscore-edhoc}} is used, when running EDHOC both with AS and with RS.

These two optimizations used together result in the most efficient interaction between C and RS, as consisting of only two roundtrips to upload the access token, run EDHOC and access the protected resource at RS.

~~~~~~~~~~~ aasvg
    C                                 AS                             RS
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC+OSCORE request to /token  |                              |
M03 |--------------------------------->|                              |
    |  - EDHOC message_3               |                              |
    |      ID_CRED_I identifies        |                              |
    |         CRED_I = AUTH_CRED_C     |                              |
    |         by reference             |                              |
    |  --- --- ---                     |                              |
    |  - OSCORE-protected part         |                              |
    |      Token request               |                              |
    |         'req_cnf' identifies     |                              |
    |         AUTH_CRED_C by reference |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M04 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  'ace_profile' specifies the     |                              |
    |  ACE profile "coap_edhoc_oscore" |                              |
    |                                  |                              |
    |  'edhoc_info' specifies:         |                              |
    |     {                            |                              |
    |       e'session_id' : h'01',     |                              |
    |       e'cipher_suites' : 2,      |                              |
    |       e'methods' : 3             |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |  - the 'cnf' claim specifies     |                              |
    |    AUTH_CRED_C by value          |                              |
    |  - the 'edhoc_info' claim        |                              |
    |    specifies the same as         |                              |
    |    'edhoc_info' above            |                              |
    |                                  |                              |

     Possibly after chain verification, the Client adds AUTH_CRED_RS
     to the set of its trusted peer authentication credentials,
     relying on AS as trusted provider

    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M05 |---------------------------------------------------------------->|
    |                                  |                              |

     Possibly after chain verification, RS adds AUTH_CRED_C
     to the set of its trusted peer authentication credentials,
     relying on AS as trusted provider

    |                                  |                              |
    |  EDHOC message_2                 |                              |
M06 |<----------------------------------------------------------------|
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC+OSCORE request to /r      |                              |
M07 |---------------------------------------------------------------->|
    |  - EDHOC message_3               |                              |
    |      EAD_3 contains access token |                              |
    |      ID_CRED_I identifies        |                              |
    |         CRED_I = AUTH_CRED_C     |                              |
    |         by reference             |                              |
    |  --- --- ---                     |                              |
    |  - OSCORE-protected part         |                              |
    |      Application request to /r   |                              |
    |                                  |                              |

     After the EDHOC processing is completed, access control
     is enforced on the rebuilt OSCORE-protected request,
     like if it had been sent stand-alone

    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M08 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~

# Profile Requirements # {#sec-profile-requirements}

This section lists the specifications of this profile based on the requirements of the framework, as requested in {{Section C of RFC9200}}.

* Optionally, define new methods for the client to discover the necessary permissions and AS for accessing a resource, different from the one proposed in {{RFC9200}}: Not specified

* Optionally, specify new grant types: Not specified

* Optionally, define the use of client certificates as client credential type: C can use authentication credentials of any type admitted by the EDHOC protocol, including public key certificates such as X.509 and C509 certificates.

* Specify the communication protocol the client and RS must use: CoAP

* Specify the security protocol the client and RS must use to protect their communication: OSCORE

* Specify how the client and RS mutually authenticate: Explicitly, by successfully executing the EDHOC protocol, after which a common OSCORE Security Context is exported from the EDHOC session. As per the EDHOC authentication method used during the EDHOC session, authentication is provided by digital signatures, or by Message Authentication Codes (MACs) computed from an ephemeral-static ECDH shared secret.

* Specify the proof-of-possession protocol(s) and how to select one, if several are available. Also specify which key types (e.g., symmetric/asymmetric) are supported by a specific proof-of-possession protocol: proof-of-possession is first achieved by RS when successfully processing EDHOC message\_3 during the EDHOC session with C, through EDHOC algorithms and symmetric EDHOC session keys. Also, proof-of-possession is later achieved by C when receiving from RS: i) the optional EDHOC message\_4 during the EDHOC session with RS, through EDHOC algorithms and symmetric EDHOC session keys; or ii) the first response protected with the OSCORE Security Context established after the EDHOC session with RS, through OSCORE algorithms and OSCORE symmetric keys derived from the completed EDHOC session.

* Specify a unique ace_profile identifier: coap_edhoc_oscore

* If introspection is supported, specify the communication and security protocol for introspection: HTTP/CoAP (+ TLS/DTLS/OSCORE)

* Specify the communication and security protocol for interactions between client and AS: HTTP/CoAP (+ TLS/DTLS/OSCORE)

* Specify if/how the authz-info endpoint is protected, including how error responses are protected: Not protected

* Optionally, define methods of token transport other than the authz-info endpoint: C can upload the access token when executing EDHOC with RS, by including the access token in the EAD\_3 field of EDHOC message\_3 (see {{edhoc-exec}}).

# CDDL Model # {#sec-cddl-model}
{:removeinrfc}

~~~~~~~~~~~~~~~~~~~~ CDDL
; ACE Profiles
coap_edhoc_oscore = 4

; OAuth Parameters CBOR Mappings
edhoc_info_param = 47

; CBOR Web Token (CWT) Claims
edhoc_info_claim = 41

; CWT Confirmation Methods
x5chain = 5
x5bag = 6
x5t = 7
x5u = 8
c5c = 9
c5b = 10
c5t = 11
c5u = 12
kcwt = 13
kccs = 14

; EDHOC Information
session_id = 0
methods = 1
cipher_suites = 2
message_4 = 3
comb_req = 4
uri_path = 5
osc_ms_len = 6
osc_salt_len = 7
osc_version = 8
cred_types = 9
id_cred_types = 10
eads = 11
initiator = 12
responder = 13
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -04 to -05 ## {#sec-04-05}

* CBOR diagnostic notation uses placeholders from a CDDL model.

* Explicit registration policies for the new IANA registry.

* Editorial fixes and improvements.

## Version -03 to -04 ## {#sec-03-04}

* Fixed column name and prefilling of the "EDHOC Information" registry.

* Added EDHOC_Information Parameters originally in draft-tiloca-lake-app-profiles-00.

* Removed the case of transporting access token in EAD_1

* Removed redundant normative text

* Clarifications of association between access token, session_id, EDHOC session and OSCORE security context

* Updated references.

* Editorial fixes and improvements.

## Version -02 to -03 ## {#sec-02-03}

* Restructured presentation of content.

* Simplified description of the use of EDHOC_Information.

* Merged the concepts of EDHOC "session_id" and identifier of token series.

* Enabled the transport of the access token also in EDHOC EAD_3.

* Defined semantics of the newly defined CWT/JWT Confirmation Methods.

* Clarifications and editorial improvements.

## Version -01 to -02 ## {#sec-01-02}

* Removed use of EDHOC_KeyUpdate.

* The Security Context is updated either by KUDOS or a rerun of EDHOC.

* The alternative workflow (AS token posting) is specified in separate draft.

* Fixed and updated examples.

* Editorial improvements.

## Version -00 to -01 ## {#sec-00-01}

* Fixed semantics of the ead_value for transporting an Access Token in the EAD_1 field.

* Error handling aligned with EDHOC.

* Precise characterization of the EDHOC execution considered for EDHOC-KeyUpdate.

* Fixed message exchange examples.

* Added appendix with profile requirements.

* Updated references.

* Clarifications and editorial improvements.

# Acknowledgments # {#acknowldegment}
{:numbered="false"}

The authors sincerely thank {{{Christian Amsüss}}} and {{{Carsten Bormann}}} for their comments and feedback.

This work was supported by the Sweden's Innovation Agency VINNOVA within the EUREKA CELTIC-NEXT project CYPRESS; and by the H2020 project SIFIS-Home (Grant agreement 952652).
