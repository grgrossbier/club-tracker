#[macro_use]
extern crate actix_web;

use actix_web::{
    dev::Payload,
    web,
    App,
    FromRequest,
    HttpRequest,
    HttpResponse,
    HttpServer,
    Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use futures::future::{ready, Ready};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::future::Future;
use uuid::Uuid;

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use log::info;
use serde_json::Value;
use serde_json::json;
use std::pin::Pin;
use actix_files::Files;



///////////////////////////////// main() ////////////////////////////////////////////////

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("api.log")?;

    Builder::new()
        .target(env_logger::Target::Pipe(Box::new(file)))
        .filter_level(log::LevelFilter::Info)
        .init();

    println!("Starting up...");  // Add debug prints
    
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    println!("Got database URL");  // Add debug prints
    
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");
    
    println!("Connected to database");  // Add debug prints

    HttpServer::new(move || {
        println!("Setting up server...");  // Add debug prints
        App::new()
            .wrap(Logging)
            .app_data(web::Data::new(AppState {
                db: db_pool.clone(),
            }))
            // Serve API routes under /api prefix
            .service(
                web::scope("/api")
                    .service(create_user)
                    .service(add_club)
                    .service(remove_club)
                    .service(get_all_clubs)
                    .service(get_club_by_distance)
                    .service(remove_all_clubs),
            )
            // Serve static files
            .service(Files::new("/", "./static").index_file("index.html"))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}





/////////////////////////////// Requests / Data / Struct Setup //////////////////////////////////

// Structures
#[derive(Serialize, Deserialize)]
struct User {
    id:       Uuid,  // A UUID is a unique identifier. UUIDs are also used for the API key (as a string)
    username: String,
    api_key:  String,
}

#[derive(Serialize, Deserialize)]
struct Club {
    id:       Uuid,
    user_id:  Uuid,
    name:     String,
    distance: i32,  // TODO: Add angle of attack as Option<u8>
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AddClubsRequest {
    clubs: Vec<ClubInfo>,
}

#[derive(Deserialize)]
struct RemoveClubsRequest {
    clubs: Vec<String>,
}

#[derive(Deserialize)]
struct GetClubByDistanceRequest {
    distance: i32,
}

// Database connection pool
// Manages a shared state across application. In this case the connection to Postgres
struct AppState {
    db: Pool<Postgres>,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct ClubInfo {
    name: String,
    distance: i32,
}


/////////////////////// Helper functions ///////////////////////////////////////////


// Try to pull a key from the data base. Error if not found.
async fn verify_api_key(db: &Pool<Postgres>, api_key: &str) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT id FROM users WHERE api_key = $1",
        api_key
    )
    .fetch_optional(db)
    .await?
    .ok_or(sqlx::Error::RowNotFound)
}

fn generate_api_key() -> String { Uuid::new_v4().to_string() }

struct ApiKey(String);

impl FromRequest for ApiKey {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let api_key = req
            .headers()
            .get("X-API-Key")
            .and_then(|header| header.to_str().ok())
            .map(|s| s.to_string());

        match api_key {
            Some(key) => ready(Ok(ApiKey(key))),
            None => ready(Err(actix_web::error::ErrorUnauthorized(
                "API Key not provided",
            ))),
        }
    }
}




////////////////////////////// API Endpoints /////////////////////////////////////////////////////

#[post("/users")]
async fn create_user(
    state: web::Data<AppState>,
    user_req: web::Json<CreateUserRequest>,
) -> impl Responder {
    let api_key = generate_api_key();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    // Check if the username already exists for this user
    match sqlx::query!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
        user_req.username,
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(row) => {
            let exists = row.exists.unwrap_or(false);
            if exists {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    message: "A user by the same name already exists.".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "Failed to check for existing user".to_string(),
            });
        }
    }

    let password_hash = argon2
        .hash_password(user_req.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    match sqlx::query!(
        "INSERT INTO users (username, password_hash, api_key) VALUES ($1, $2, $3) RETURNING id",
        user_req.username,
        password_hash,
        api_key
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(User {
            id: user.id,
            username: user_req.username.clone(),
            api_key,
        }),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/clubs")]
async fn add_club(
    state: web::Data<AppState>,
    clubs_req: web::Json<AddClubsRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            // Extract vectors of names and distances for all clubs
            let names: Vec<String> = clubs_req.clubs.iter().map(|c| c.name.clone()).collect();
            let distances: Vec<i32> = clubs_req.clubs.iter().map(|c| c.distance).collect();

            // Use UPSERT (INSERT ... ON CONFLICT DO UPDATE) for all clubs
            match sqlx::query!(
                "WITH changes AS (
                    INSERT INTO clubs (user_id, name, distance)
                    SELECT $1, unnest($2::text[]), unnest($3::integer[])
                    ON CONFLICT (user_id, name) DO UPDATE 
                    SET distance = EXCLUDED.distance
                    RETURNING name, distance,
                        CASE 
                            WHEN xmax = 0 THEN 'insert'
                            ELSE 'update'
                        END as change_type
                )
                SELECT name, distance, change_type FROM changes",
                user_id,
                &names as &[String],
                &distances as &[i32]
            )
            .fetch_all(&state.db)
            .await
            {
                Ok(results) => {
                    let mut added_clubs = Vec::new();
                    let mut updated_clubs = Vec::new();

                    for row in results {
                        let club_info = ClubInfo {
                            name: row.name,
                            distance: row.distance,
                        };

                        // Now we have a more explicit field name
                        if row.change_type.unwrap() == "insert" {
                            added_clubs.push(club_info);
                        } else {
                            updated_clubs.push(club_info);
                        }
                    }

                    HttpResponse::Ok().json(json!({
                        "status": "success",
                        "added_clubs": added_clubs,
                        "updated_clubs": updated_clubs,
                        "added_count": added_clubs.len(),
                        "updated_count": updated_clubs.len()
                    }))
                },
                Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
                    message: "Failed to insert/update clubs".to_string(),
                }),
            }
        }
        Err(_) => HttpResponse::Unauthorized().json(ErrorResponse {
            message: "Invalid API key".to_string(),
        }),
    }
}

#[delete("/clubs")]
async fn remove_club(
    state: web::Data<AppState>,
    clubs_req: web::Json<RemoveClubsRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            let mut removed_clubs = Vec::new();
            let mut not_found_clubs = Vec::new();

            // Process each club
            match sqlx::query!(
                "DELETE FROM clubs WHERE name = ANY($1) AND user_id = $2 RETURNING name",
                &clubs_req.clubs,  // Use ANY for efficient batch deletion
                user_id
            )
            .fetch_all(&state.db)
            .await
            {
                Ok(results) => {
                    // Track which clubs were actually deleted
                    let removed_names: Vec<String> = results.into_iter()
                        .map(|r| r.name)
                        .collect();
                    
                    // Find which clubs weren't deleted
                    not_found_clubs = clubs_req.clubs
                        .iter()
                        .filter(|name| !removed_names.contains(name))
                        .cloned()
                        .collect();
                    
                    removed_clubs = removed_names;
                },
                Err(_) => {
                    return HttpResponse::InternalServerError().json(ErrorResponse {
                        message: "Failed to remove clubs".to_string(),
                    });
                }
            }

            // Always return success, just report what happened
            HttpResponse::Ok().json(json!({
                "status": "success",
                "removed_clubs": removed_clubs,
                "not_found_clubs": not_found_clubs,
                "removed_count": removed_clubs.len(),
                "not_found_count": not_found_clubs.len()
            }))
        }
        Err(_) => HttpResponse::Unauthorized().json(ErrorResponse {
            message: "Invalid API key".to_string(),
        }),
    }
}

#[derive(Deserialize)]
struct RemoveAllClubsRequest {
    confirmation: String  // Must match "DELETE ALL MY CLUBS"
}

#[delete("/clubs/all")]
async fn remove_all_clubs(
    state: web::Data<AppState>,
    req: web::Json<RemoveAllClubsRequest>,
    api_key: ApiKey,
) -> impl Responder {
    const CONFIRMATION_TEXT: &str = "DELETE ALL MY CLUBS";
    
    if req.confirmation != CONFIRMATION_TEXT {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: format!("Must provide confirmation text: '{}'", CONFIRMATION_TEXT)
        });
    }
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            match sqlx::query!(
                "DELETE FROM clubs WHERE user_id = $1 RETURNING name",
                user_id
            )
            .fetch_all(&state.db)
            .await
            {
                Ok(deleted) => {
                    let removed_clubs: Vec<String> = deleted.into_iter()
                        .map(|r| r.name)
                        .collect();
                    
                    HttpResponse::Ok().json(json!({
                        "status": "success",
                        "removed_clubs": removed_clubs,
                        "count": removed_clubs.len()
                    }))
                },
                Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
                    message: "Failed to remove clubs".to_string(),
                })
            }
        }
        Err(_) => HttpResponse::Unauthorized().json(ErrorResponse {
            message: "Invalid API key".to_string(),
        })
    }
}

#[get("/clubs")]
async fn get_all_clubs(state: web::Data<AppState>, api_key: ApiKey) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            match sqlx::query_as!(
                ClubInfo,
                "SELECT name, distance FROM clubs 
                WHERE user_id = $1
                ORDER BY distance ASC
                ",
                user_id
            )
            .fetch_all(&state.db)
            .await
            {
                Ok(clubs) => HttpResponse::Ok().json(clubs),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

#[post("/clubs/by-distance")]
async fn get_club_by_distance(
    state: web::Data<AppState>,
    distance_req: web::Json<GetClubByDistanceRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            let target_distance = distance_req.distance;
            let lower_bound = target_distance - 20;
            let upper_bound = target_distance + 30;

            match sqlx::query_as!(
                ClubInfo,
                "SELECT name, distance FROM clubs 
                WHERE user_id = $1 AND distance >= $2
                ORDER BY distance ASC
                LIMIT 1",
                user_id,
                target_distance
            )
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(club)) => {
                    let nearby_clubs = sqlx::query_as!(
                        ClubInfo,
                        "SELECT name, distance FROM clubs 
                        WHERE user_id = $1 AND distance BETWEEN $2 AND $3
                        ORDER BY distance ASC",
                        user_id,
                        lower_bound,
                        upper_bound,
                    )
                    .fetch_all(&state.db)
                    .await
                    .unwrap_or_default();

                    HttpResponse::Ok().json((club, nearby_clubs))
                }
                Ok(None) => HttpResponse::NotFound().finish(),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

use env_logger::Builder;
use std::fs::OpenOptions;





/////////////////////////////// Logging Setup ////////////////////////////////////////

/// Middleware for logging HTTP requests and responses.
/// /// Use with `App::wrap(Logging)`.
pub struct Logging;

impl<S, B> Transform<S, ServiceRequest> for Logging
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = LoggingMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(LoggingMiddleware { service }))
    }
}

pub struct LoggingMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for LoggingMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().to_string();
        let path = req.path().to_string();
        let query_string = req.query_string().to_string();
        let headers = format!("{:?}", req.headers());

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            // Log the request details
            info!(
                "Request: {} {} \nQuery: {} \nHeaders: {}",
                method, path, query_string, headers
            );

            // Log the response status
            info!("Response Status: {}", res.status());

            Ok(res)
        })
    }
}

