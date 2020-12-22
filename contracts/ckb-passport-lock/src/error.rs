use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    InvalidArgument = 5,
    // Add customized errors here...
    LoadPrefilledData,
    WrongPubKey,
    RSAPubKeySigLengthError,
    ISO97962RSAVerifyError,
    ISO97962InvalidArg1 = 10,
    ISO97962InvalidArg2,
    ISO97962InvalidArg3,
    ISO97962InvalidArg4,
    ISO97962InvalidArg5,
    ISO97962InvalidArg6 = 15,
    ISO97962InvalidArg7,
    ISO97962InvalidArg8,
    ISO97962InvalidArg9,
    ISO97962MismatchHash,
    ISO97962NotFullMsg = 20,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

