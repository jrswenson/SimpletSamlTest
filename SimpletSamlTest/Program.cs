using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Protocols;
using ComponentSpace.SAML2.Protocols;

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using static System.Net.Mime.MediaTypeNames;

namespace SimpletSamlTest
{

    class Program
    {
        private static string BuildResponseURL(string strResponse, string strPatientURL)
        {
            var sb = new StringBuilder();
            var xml = new XmlDocument();
            xml.LoadXml(Util.DecodeBase64(strResponse));
            var samlResponse = new SAMLResponse(xml.DocumentElement);

            foreach (SAMLAssertion samlAssertion in samlResponse.Assertions)
            {
                foreach (var attributeStatement in samlAssertion.GetAttributeStatements())
                {
                    foreach (SAMLAttribute samlAttribute in attributeStatement.Attributes)
                    {
                        if (samlAttribute.Name != "idptoken") continue;

                        sb.Append(strPatientURL);
                        sb.Append("&idptoken=");
                        sb.Append(samlAttribute.Values.FirstOrDefault());
                    }
                }
            }

            return sb.ToString();
        }

        private static string BuildSAMLRequest(IList<string> attributes)
        {
            var strIssuer = "https://sso.staging.gnohie.org/MirthSignOn-idp/ssoresp";
            var samlResponse = new SAMLResponse();
            samlResponse.Issuer = new Issuer(strIssuer);
            samlResponse.Destination = strIssuer;

            var samlAssertion = new SAMLAssertion();
            samlAssertion.Issuer = new Issuer(strIssuer);
            samlAssertion.Subject = new Subject(new NameID(attributes.ElementAt(1), null, null, SAMLIdentifiers.NameIdentifierFormats.EmailAddress, null));
            samlAssertion.Conditions = new Conditions(new TimeSpan(1, 0, 0));

            var authnStatement = new AuthnStatement();
            authnStatement.AuthnContext = new AuthnContext();
            authnStatement.AuthnContext.AuthnContextClassRef = new AuthnContextClassRef(SAMLIdentifiers.AuthnContextClasses.PasswordProtectedTransport);
            samlAssertion.Statements.Add(authnStatement);

            var attributeStatement = new AttributeStatement();
            attributeStatement.Attributes.Add(new SAMLAttribute("member", SAMLIdentifiers.AttributeNameFormats.Basic, null, attributes.ElementAt(0)));
            samlAssertion.Statements.Add(attributeStatement);

            attributeStatement = new AttributeStatement();
            attributeStatement.Attributes.Add(new SAMLAttribute("mail", SAMLIdentifiers.AttributeNameFormats.Basic, null, attributes.ElementAt(1)));
            samlAssertion.Statements.Add(attributeStatement);

            attributeStatement = new AttributeStatement();
            attributeStatement.Attributes.Add(new SAMLAttribute("cn", SAMLIdentifiers.AttributeNameFormats.Basic, null, attributes.ElementAt(2)));
            samlAssertion.Statements.Add(attributeStatement);

            attributeStatement = new AttributeStatement();
            attributeStatement.Attributes.Add(new SAMLAttribute("uid", SAMLIdentifiers.AttributeNameFormats.Basic, null, attributes.ElementAt(3)));
            samlAssertion.Statements.Add(attributeStatement);

            samlResponse.Assertions.Add(samlAssertion);

            if (true)
            {
                var x509Certificate = Util.LoadSignKeyAndCertificate();
                var signedXml = new SignedXml(samlResponse.ToXml());
                signedXml.SigningKey = x509Certificate.PrivateKey;

                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(x509Certificate));
                signedXml.KeyInfo = keyInfo;

                // Create a reference to be signed.
                var reference = new Reference();
                reference.Uri = "#" + samlAssertion.ID;

                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);
                signedXml.AddReference(reference);
                signedXml.ComputeSignature();

                samlResponse.Signature = signedXml.GetXml();

            }

            //samlResponse.Status = new Status(SAMLIdentifiers.PrimaryStatusCodes.Success, null);

            var result = samlResponse.ToXml().OuterXml.ToString();
            File.WriteAllText("SAMLPayload.xml", result);
            return Util.EncodeToBase64(result);
        }

        public static void PostSSO()
        {
            var attributes = new List<string> { "MirthResultsUser", "aabram@lsuhsc.edu", "Amir Abrams", "aabram", "https://nwhin.gnohie.org/mirthresults/Patient.action?embed=&subject.subjectKey=201138&siteGlobalId=GNOHIE" };
            using (var client = new WebClient())
            {
                //client.Credentials = new NetworkCredential("jswens", "ews73Lsusso");
                var saml = BuildSAMLRequest(attributes);
                var reqparm = new NameValueCollection();
                reqparm.Add("SAMLResponse", saml);
                string ret;
                try
                {
                    var responsebytes = client.UploadValues("https://sso.staging.gnohie.org/MirthSignOn-idp/ssoresp?", "POST", reqparm);
                    var responsebody = Encoding.UTF8.GetString(responsebytes);
                    ret = BuildResponseURL(responsebody, "");
                }
                catch (Exception ex)
                {
                    ret = ex.Message;
                }

                Debug.WriteLine(ret);
            }
        }

        static void Main(string[] args)
        {

            PostSSO();

            // Console.ReadKey();
        }
    }

    public class AppSettings
    {
        public string assertionConsumerServiceUrl = "http://localhost:49573/SamlConsumer/Consume.aspx";
        public string issuer = "test-app";
    }

    public class AccountSettings
    {
        public string certificate = "-----BEGIN CERTIFICATE-----MIIEMTCCAxmgAwIBAgIDCDPUMA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMSAwHgYDVQQDExdSYXBpZFNTTCBTSEEyNTYgQ0EgLSBHMzAeFw0xNTExMDkxMTI0MDNaFw0xNjExMTEwNjAxMDVaMB8xHTAbBgNVBAMMFCouc3RhZ2luZy5nbm9oaWUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZu0lpkWoGONGouvL5cXDlgSM3EbYcHEW8qJ1fL/bEwe63R1DT/Fc2bfTL4f8OOWb+8ejd1nNI2dbjU3wXFsNTl2X8aYM9ixO1X4s9Jq2hKxRNQ994lR970coeGmost/+8RhVR5ifuVTjSUQEHrBYxhQQoHEHpA3H5cDBUDagBaZnpitqykAPQzsyGAf7ruimZrUxZnslxbXsWvtk5Ecf5o4uUR0NO1/rw8zFVlfD/CHhBvg6l7Wk2yqqZ9AvMh3iFMQ+QW+zRhaIkU1q0+8hO9jTBMDmy2A9GDDdkNHEuybRRvxRgweIGC15fTXT0QZwdt+iij4ymDrTtubyYs4ewIDAQABo4IBTDCCAUgwHwYDVR0jBBgwFoAUw5zz/NNGCDS7zkZ/oHxb8+IIy1kwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vZ3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vZ3Yuc3ltY2IuY29tL2d2LmNydDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdEQQYMBaCFCouc3RhZ2luZy5nbm9oaWUub3JnMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9ndi5zeW1jYi5jb20vZ3YuY3JsMAwGA1UdEwEB/wQCMAAwQQYDVR0gBDowODA2BgZngQwBAgEwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cucmFwaWRzc2wuY29tL2xlZ2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAhfAoW6OZf6K5m12vqyM62HqyYQypVGYcR3LBVaIR6jOwEQEjsh3LVmP2zI0dhsxqwovA453lq51WLFTfncfQQNtoZtdcquOUKBe1mAAtRUtOZDxWvvaWaBR1v36n3cgHX1QROFPweN0tSOQKgsOZb5OG2bK4K2rtKdTvbuQCCPFDAekdgPI0K5W6ttH9CBlQ7HQk0ma6A7UFdBYBbLf5BcNeyjxc3QbeXsQbN4Sy6gjWwM6CTNrBYXLXVt5wBbvN0PEPHjQqKK+vkwYTUlxmInO+PZbRTHtbUNP0CAq3Z26cZSU6NDHdbWWGooEOpW4tPDpkJRxm6pl0wmRGqKxs4-----END CERTIFICATE-----";
        public string idp_sso_target_url = "https://nwhin.staging.gnohie.org/MirthSignOn-idp/ssoresp";
    }


    public class Certificate
    {
        public X509Certificate2 cert;

        public void LoadCertificate(string certificate)
        {
            cert = new X509Certificate2();
            cert.Import(StringToByteArray(certificate));
        }

        public void LoadCertificate(byte[] certificate)
        {
            cert = new X509Certificate2();
            cert.Import(certificate);
        }

        private byte[] StringToByteArray(string st)
        {
            byte[] bytes = new byte[st.Length];
            for (int i = 0; i < st.Length; i++)
            {
                bytes[i] = (byte)st[i];
            }
            return bytes;
        }
    }

    public class Response
    {
        private XmlDocument xmlDoc;
        private AccountSettings accountSettings;
        private Certificate certificate;

        public Response(AccountSettings accountSettings)
        {
            this.accountSettings = accountSettings;
            certificate = new Certificate();
            certificate.LoadCertificate(accountSettings.certificate);
        }

        public void LoadXml(string xml)
        {
            xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.XmlResolver = null;
            xmlDoc.LoadXml(xml);
        }

        public void LoadXmlFromBase64(string response)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            LoadXml(enc.GetString(Convert.FromBase64String(response)));
        }

        public bool IsValid()
        {
            bool status = false;

            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);
            return signedXml.CheckSignature(certificate.cert, true);
        }

        public string GetNameID()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            XmlNode node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager);
            return node.InnerText;
        }
    }

    public class AuthRequest
    {
        public string id;
        private string issue_instant;
        private AppSettings appSettings;
        private AccountSettings accountSettings;

        public enum AuthRequestFormat
        {
            Base64 = 1
        }

        public AuthRequest(AppSettings appSettings, AccountSettings accountSettings)
        {
            this.appSettings = appSettings;
            this.accountSettings = accountSettings;

            id = "_" + System.Guid.NewGuid().ToString();
            issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        public string GetRequest(AuthRequestFormat format)
        {
            using (var sw = new StringWriter())
            {
                XmlWriterSettings xws = new XmlWriterSettings();
                xws.OmitXmlDeclaration = true;

                using (XmlWriter xw = XmlWriter.Create(sw, xws))
                {
                    xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("ID", id);
                    xw.WriteAttributeString("Version", "2.0");
                    xw.WriteAttributeString("IssueInstant", issue_instant);
                    xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                    xw.WriteAttributeString("AssertionConsumerServiceURL", appSettings.assertionConsumerServiceUrl);

                    xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xw.WriteString(appSettings.issuer);
                    xw.WriteEndElement();

                    xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
                    xw.WriteAttributeString("AllowCreate", "true");
                    xw.WriteEndElement();

                    xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("Comparison", "exact");
                    xw.WriteEndElement();

                    xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                    xw.WriteEndElement();

                    xw.WriteEndElement();
                }

                if (format == AuthRequestFormat.Base64)
                {
                    byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(sw.ToString());
                    return System.Convert.ToBase64String(toEncodeAsBytes);
                }

                return null;
            }
        }
    }
}
