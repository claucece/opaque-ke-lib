mod opaque_auth {
    use argon2::Argon2;
    use rand::CryptoRng;
    use rand::RngCore;

    use opaque_ke::ciphersuite::CipherSuite;
    use opaque_ke::errors::ProtocolError;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
        ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
        ClientRegistrationStartResult, CredentialResponse, RegistrationResponse,
    };

    pub struct DefaultCipherSuite;

    // The default suite to use
    impl CipherSuite for DefaultCipherSuite {
        type OprfCs = opaque_ke::Ristretto255;
        type KeGroup = opaque_ke::Ristretto255;
        type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
        type Ksf = Argon2<'static>;
    }

    pub fn client_registration_start<R: CryptoRng + RngCore>(
        client_rng: &mut R,
        password: &[u8],
    ) -> Result<ClientRegistrationStartResult<DefaultCipherSuite>, ProtocolError> {
        ClientRegistration::<DefaultCipherSuite>::start(client_rng, password)
    }

    // TODO: or should we return &[u8]?
    pub fn client_registation_start_serialize(
        registration: ClientRegistrationStartResult<DefaultCipherSuite>,
    ) -> Vec<u8> {
        registration.message.serialize().to_vec()
    }

    pub fn client_registration_finish<R: CryptoRng + RngCore>(
        client_rng: &mut R,
        password: &[u8],
        registration: ClientRegistrationStartResult<DefaultCipherSuite>,
        response: &[u8],
    ) -> Result<ClientRegistrationFinishResult<DefaultCipherSuite>, ProtocolError> {
        let response_st = RegistrationResponse::deserialize(response)?;

        registration.state.finish(
            client_rng,
            password,
            response_st,
            ClientRegistrationFinishParameters::default(),
        )
    }

    pub fn client_login_start<R: CryptoRng + RngCore>(
        client_rng: &mut R,
        password: &[u8],
    ) -> Result<ClientLoginStartResult<DefaultCipherSuite>, ProtocolError> {
        ClientLogin::<DefaultCipherSuite>::start(client_rng, password)
    }

    // TODO: or should we return &[u8]?
    pub fn client_login_start_serialize(
        login: ClientLoginStartResult<DefaultCipherSuite>,
    ) -> Vec<u8> {
        login.message.serialize().to_vec()
    }

    pub fn client_login_finish(
        password: &[u8],
        login: ClientLoginStartResult<DefaultCipherSuite>,
        response: &[u8],
    ) -> Result<ClientLoginFinishResult<DefaultCipherSuite>, ProtocolError> {
        let response_st = CredentialResponse::deserialize(response)?;
        login.state.finish(
            password,
            response_st,
            ClientLoginFinishParameters::default(),
        )
    }
}

pub use opaque_auth::{
    client_login_finish, client_login_start, client_login_start_serialize,
    client_registation_start_serialize, client_registration_finish, client_registration_start,
    DefaultCipherSuite,
};
