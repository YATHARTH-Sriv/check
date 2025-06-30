use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

// --- Main Application Setup ---

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "solana_http_server=debug,tower_http=debug",
        ))
        .init();

    // Build our application router
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));
    
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a number");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    // Run the server
    // let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

// --- Custom Error and Response Types ---

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Missing required fields")]
    MissingFields,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal server error: {0}")]
    InternalError(String),
}

// Custom response for success and error cases to match the spec
#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> impl IntoResponse {
        Json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
        })
    }
}

// This allows our `AppError` to be converted into a valid HTTP response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::MissingFields => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(error_message),
        });

        (status, body).into_response()
    }
}

// --- Helper Functions ---

fn pubkey_from_str(s: &str) -> Result<Pubkey, AppError> {
    Pubkey::from_str(s).map_err(|e| AppError::InvalidInput(format!("Invalid public key format: {}", e)))
}

// --- Endpoint Handlers and Associated Structs ---

// 1. Generate Keypair
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    ApiResponse::success(KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: keypair.to_base58_string(),
    })
}

// 2. Create Token
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct SerializableAccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

impl From<AccountMeta> for SerializableAccountMeta {
    fn from(meta: AccountMeta) -> Self {
        Self {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }
    }
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<SerializableAccountMeta>,
    instruction_data: String,
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mint_authority = pubkey_from_str(&payload.mint_authority)?;
    let mint = pubkey_from_str(&payload.mint)?;

    let instruction = spl_token::instruction::initialize_mint(
        &spl_token::ID,
        &mint,
        &mint_authority,
        None, // freeze authority
        payload.decimals,
    )
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.into_iter().map(SerializableAccountMeta::from).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}

// 3. Mint Token
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mint_pubkey = pubkey_from_str(&payload.mint)?;
    let destination_pubkey = pubkey_from_str(&payload.destination)?;
    let authority_pubkey = pubkey_from_str(&payload.authority)?;

    let instruction = spl_token::instruction::mint_to(
        &spl_token::ID,
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[], // Required signers for multisig, empty for single signer
        payload.amount,
    )
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(ApiResponse::success(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.into_iter().map(SerializableAccountMeta::from).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}

// 4. Sign Message
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(AppError::MissingFields);
    }
    
    let keypair = Keypair::from_base58_string(&payload.secret);

    let signature = keypair.sign_message(payload.message.as_bytes());

    Ok(ApiResponse::success(SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    }))
}

// 5. Verify Message
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let pubkey = pubkey_from_str(&payload.pubkey)?;
    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature)
        .map_err(|e| AppError::InvalidInput(format!("Invalid base64 signature: {}", e)))?;
    
    let signature = solana_sdk::signature::Signature::try_from(signature_bytes)
        .map_err(|e| AppError::InvalidInput(format!("Invalid signature format: {:?}", e)))?;
        
    let is_valid = signature.verify(&pubkey.to_bytes(), payload.message.as_bytes());

    Ok(ApiResponse::success(VerifyMessageResponse {
        valid: is_valid,
        message: payload.message,
        pubkey: payload.pubkey,
    }))
}

// 6. Send SOL
#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

// Response for SOL transfer must match the specific format in the spec
#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<impl IntoResponse, AppError> {
    let from_pubkey = pubkey_from_str(&payload.from)?;
    let to_pubkey = pubkey_from_str(&payload.to)?;

    // Basic validation
    if from_pubkey == to_pubkey {
        return Err(AppError::InvalidInput("Sender and recipient addresses cannot be the same.".to_string()));
    }
    if payload.lamports == 0 {
        return Err(AppError::InvalidInput("Lamports must be greater than zero.".to_string()));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    Ok(ApiResponse::success(SendSolResponse {
        program_id: instruction.program_id.to_string(),
        // Spec requires an array of strings for accounts here
        accounts: instruction.accounts.into_iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}


// 7. Send Token
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// Response for token transfer must match the specific format in the spec
#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")] // Match spec's camelCase
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let owner_pubkey = pubkey_from_str(&payload.owner)?;
    let mint_pubkey = pubkey_from_str(&payload.mint)?;
    let destination_ata_pubkey = pubkey_from_str(&payload.destination)?;

    // A token transfer instruction requires the owner's Associated Token Account (ATA)
    // as the source, not the owner's main wallet address.
    let source_ata_pubkey = get_associated_token_address(&owner_pubkey, &mint_pubkey);

    let instruction = spl_token::instruction::transfer(
        &spl_token::ID,
        &source_ata_pubkey,
        &destination_ata_pubkey,
        &owner_pubkey, // The owner of the source ATA is the signer
        &[],
        payload.amount,
    )
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Map to the specific response structure for this endpoint
    let response_accounts = instruction.accounts.into_iter().map(|acc| SendTokenAccountMeta {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    Ok(ApiResponse::success(SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts: response_accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }))
}