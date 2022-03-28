use nom::multi::length_data;
use nom::number::streaming::be_u16;
use nom::IResult;
use nom_derive::*;

/// RSA parameters, defined in [RFC2246] section 7.4.3
#[derive(Debug, PartialEq, NomBE, Hash)]
pub struct ServerRSAParams<'a> {
    /// The modulus of the server's temporary RSA key.
    #[nom(Parse = "length_data(be_u16)")]
    pub modulus: &'a [u8],
    /// The public exponent of the server's temporary RSA key.
    #[nom(Parse = "length_data(be_u16)")]
    pub exponent: &'a [u8],
}

#[inline]
pub fn parse_rsa_params(i: &[u8]) -> IResult<&[u8], ServerRSAParams> {
    ServerRSAParams::parse(i)
}