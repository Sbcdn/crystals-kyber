pub(crate) mod kyber;

pub(crate) struct Keys {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl Keys {
    pub fn new(private: &Vec<u8>, public: &Vec<u8>) -> Self {
        Keys {
            private: private.to_owned(),
            public: public.to_owned(),
        }
    }
}
