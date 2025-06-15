use comprehensive::v1::{AssemblyRuntime, Resource, resource};
use comprehensive_traits::tls_config::{Exchange, Snapshot, TlsConfigProvider};
use futures::{FutureExt, SinkExt};
use std::io::Cursor;
use std::sync::Arc;
use std::task::Context;

const USER1_KEY: &[u8] = br#"
-----BEGIN PRIVATE KEY-----
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
OlO6WJd8RtUyJzJH9yqdOjL9iqwL
-----END PRIVATE KEY-----
"#;

const USER1_CERT: &[u8] = br#"
-----BEGIN CERTIFICATE-----
MIIE+jCCAuKgAwIBAgIUeDIYdW1mfwdSgSnIfXIMCifVR0swDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEAwwCQ0EwIBcNMjQwOTI5MTE1MjU5WhgPMjA3NDA5MjcxMTUy
NTlaMBAxDjAMBgNVBAMMBXVzZXIxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEA8brEeNXpzQuORWF33tYQURahAVLSC0cCpiKOL3wVhasFaAAFuEvYCe+Y
A/TvtYQ95aJR/+yCVAV3yFqQ8OleEF3VMVUSYJ+qc/4c08RjLDEPT8PyjqpijfFS
k1CntWyO8A/c3Zkp0GPT/5rNizNuN8vLOMex7sxEBlUzfNYhwCtldoOeFfmbJLBK
sj/c6Rcw3DBcT0V8uwXXANlrWBzl68pU9RpfkAqwo1RiWA64tsD7MvKD8eTfYU5f
lo/VEqli4A6ISMJ+aG6HmawbEJQw7gmLWSKw4o7s7jWS51QicinVZvont/Zw4dWb
71brg2I31H8V+guG85Dyf8/XTUgFpkiogcDoemdAfZUV8I0WKLDzDUt6XvWxvkZS
lucO1i38Aty8gXsScVzZdYU0AG7utgwXy+LqDjOj7NMk88TAZgUjOQKslnOQngUE
mvTCA4U23oQoofz/OFk2ArHXKIDFCndLnOtX1SlBWHQgwgMBYCAZYS6EU+cMWYos
LgXWgcWO8QBKHGK64DNAfmrGX8jkXJMOktN2CUOxWes2OuzvANLxYj6vf7IMhzjm
GL7MnZqY0uwBwk8/5n5hcJxZRxAb7aP+VpvvBQkvnJ30E6o8+o4ceJEOgDt6SF1F
3xgr8XSKoM2tiRucnSuyGOY+f+HtqUv2I700bi/BNir7gKlfgScCAwEAAaNNMEsw
HwYDVR0jBBgwFoAUaoAIcSacwxgmg+9vtSuJUFqROhMwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBPAwEAYDVR0RBAkwB4IFdXNlcjEwDQYJKoZIhvcNAQELBQADggIBAHh9
wGWKqhsihF/IqR0xqqzWcUhX7GLZRcJDYAjnSIX2WA51zNbP06wvTMqWZ56FdX5k
bzAu4L3Dl1MWqDHQquFTouX7m67xbRkvdfcshubOlIkJaHTvoFN8ggl+DoIWnyqt
eWO5O697dqt3Bx7eQ2ZbK+qThUoBDzLGU0VZHGYI1L7jn3OT8iqp4WNbJ96FsuMy
r4VED3Isl0dc+u4wg633RVdJU/CIYTiwkf0UniHChowdOvWe1B5wi5IXrpUJSu3I
afqgtIQPoRXONeDHhA9PoODDr0A+Abm0pSkkIQuXXirmdmQhb7daxDcosg24HmkU
OcHGdLOlKeMGzFSZXqSoBQbvPqVWHl8xYARQTFrtT+hZkW0yl+PZTk94npHHeGB2
Edp1d7wVS4XQaj9Q7XdgBSB7tDTv2pLRiPzMQXwk1pjSWwktyErS3TBfb4J1+nEI
WF8yk1QuRq5ZCNy4NLedaD+0//Z02O47WXZ6H35LPIxa9LmfCWzzV89G6jbdaTpC
6dpvMLrAPjTr77qmLSrSWGAJGkX0sCeTUuLVDcv7XzGdbxbZSvXrcYlQr2tqU0cj
IIHEs6eE8rtiiE33c+gF4YP9aVbSpptPE23t/faY6B5I2IYxDmqQGCABLPk/tEgo
VW9jwWovVVzQ7JfPmYfuJYoLhPV9dzDT1IpiO1ma
-----END CERTIFICATE-----
"#;

const CACERT: &[u8] = br#"
-----BEGIN CERTIFICATE-----
MIIE/TCCAuWgAwIBAgIUC6P8lL7WcKXKasK4GDblgg2Yl8owDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEAwwCQ0EwIBcNMjQwOTI5MTE0NjIyWhgPMjA3NDA5MjcxMTQ2
MjJaMA0xCzAJBgNVBAMMAkNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAlGij3bX/EGzGncKyR2yQSBJjC8mpeRCSAsYsjajOaAm+3SUQ4ifNPTDRoDbU
AHbEIFa4l6h/9NapOZkRb7ctX2ELJzMa+IEpjP+U33i2tZV1m4r4LouphzzA4gkx
2voe+a3TOo73Ws0G7+hqQTpb+SQlao/TcQ16YSx65JVDjW/dPACb2bnxe1yDJOaM
DzRLtcSYlbiPyLfnF4RP6NXzNKBki4ShyEoKAjZvaIPJzjDNekJrTj5i/6xA7X2Q
w9aIDr11/Q5EfQ2pATfYJxCzhQbZBSB6qJdBVE+BAvoyCzvcCNQj/lUE+vFiNBPV
Rej6djFT539VG0YxsedInqLu8Eyth2aP4WyV4kHaBuHZIWu6TtDQnk/dZGE8zRDf
RwroMWKMxiJxJcHrB0kbgk3LY0FwiuWi+eDvkLjhwnIYz6udtf0HSrLuu7v+pV7I
+M4XrgsiLghngkYxUHDDtOZJ54qrnpyWXxh0WVoU3E7bI159U76k6wXlMt1oviwn
Yq+iPfPIhOppMdK4Jja3dKPwYnHmf7XJ0d7QBDu+FKmIwxHVyDY+uXR/KPizwPg+
pmA1GJIJa3bGE2SU4T9wRmrrw0tNQsKbBoRFMncXVJF8tAeG82w2/ECLg/lwvibP
XUnSjf+Hwmd0Wooz5wc5meI4iGh6lbV2WgFJ3wjWK1+yltcCAwEAAaNTMFEwHQYD
VR0OBBYEFGqACHEmnMMYJoPvb7UriVBakToTMB8GA1UdIwQYMBaAFGqACHEmnMMY
JoPvb7UriVBakToTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
ACE2F7/Vp1wpp1hsGf342jo1qKsySyxcigWFkaZfDHJLInzF3bm/kcYBzYTELdP+
odoMbOmfbRUbl0DsmRHWP0PtbghtnUB+b2py8zGuqTezYIIXUjcUkqlEFbFo4tQg
+s2ximUpAwI3ClgrWvuj4tHHhhjXVQo424okkyZypUXHRNaKHo+yF5VAHf7msPyy
hQuTdUSNmhzWK6/JZpuyI7NbkiVgvt1y4ymqarAuE+bbcXo0j9L+aYUv9Eij4yJC
DJVfzsKvFIeA8bpc0PRgkNLztrcBIeQOKtMUPL6oCpEbfENsrVzkMhLksTCB4kwZ
U7OpEt0D/doVudBmmUCzYwmFyaCrAPTgZzImyIe6KIeAw5xNfbFYznibi1dtepXR
dGPbSpFfsindYuKmKx03ZMgTShzpB4gM10gHl63Jo6rGNfiHaCIyMhFoXUOK6QTD
335eIQ2CT98Pe9yF7GlbroomlyIQlSKfx0EYltjxXcDVruAgL9Yx/B5b2EeK3Vpi
2G2Nrcgme5dL91KTUQyaodLTVo59hXOIIfLk6rwLASQcH+aAbjNW8ckVjLou98LX
H8nAfcEW7oPp5rv5nshDfj29ffEkGT/CLoScnKCwqA/lRjud/j3NHw89MTAk3puZ
I6snlcxZJk6CVv/lGNUJRQKgncKXgvkaVo2enAKoE6l7
-----END CERTIFICATE-----
"#;

pub(crate) struct User1(Exchange);

#[resource]
#[export(dyn TlsConfigProvider)]
impl Resource for User1 {
    fn new(
        _: comprehensive::NoDependencies,
        _: comprehensive::NoArgs,
        _: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, std::convert::Infallible> {
        let exchange = Exchange::default();
        let _ = exchange
            .writer()
            .unwrap()
            .send(Box::new(Snapshot {
                key: rustls_pemfile::private_key(&mut Cursor::new(USER1_KEY))
                    .unwrap()
                    .unwrap(),
                cert: rustls_pemfile::certs(&mut Cursor::new(USER1_CERT))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                cacert: rustls_pemfile::certs(&mut Cursor::new(CACERT))
                    .collect::<Result<Vec<_>, _>>()
                    .ok(),
            }))
            .poll_unpin(&mut Context::from_waker(std::task::Waker::noop()));
        Ok(Arc::new(Self(exchange)))
    }
}

impl TlsConfigProvider for User1 {
    fn stream(&self) -> Option<comprehensive_traits::tls_config::Reader<'_>> {
        self.0.reader()
    }
}
