#[macro_use]
extern crate actix_web;

use actix_web::{web, App, HttpServer, HttpResponse, Responder, FromRequest, HttpRequest, dev::Payload};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use uuid::Uuid;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use futures::future::{ready, Ready};

// Structures
#[derive(Serialize, Deserialize)]
struct User {
    id: Uuid,
    username: String,
    api_key: String,
}

#[derive(Serialize, Deserialize)]
struct Club {
    id: Uuid,
    user_id: Uuid,
    name: String,
    distance: i32,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AddClubRequest {
    name: String,
    distance: i32,
}

#[derive(Deserialize)]
struct RemoveClubRequest {
    club_id: Uuid,
}

#[derive(Deserialize)]
struct GetClubByDistanceRequest {
    distance: i32,
}

// Database connection pool
struct AppState {
    db: Pool<Postgres>,
}

// Helper functions
async fn verify_api_key(db: &Pool<Postgres>, api_key: &str) -> Result<Uuid, sqlx::Error> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, api_key FROM users WHERE api_key = $1",
        api_key
    )
    .fetch_optional(db)
    .await?;

    user.map(|u| u.id).ok_or(sqlx::Error::RowNotFound)
}

fn generate_api_key() -> String {
    Uuid::new_v4().to_string()
}

struct ApiKey(String);

impl FromRequest for ApiKey {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let api_key = req.headers().get("X-API-Key")
            .and_then(|header| header.to_str().ok())
            .map(|s| s.to_string());

        match api_key {
            Some(key) => ready(Ok(ApiKey(key))),
            None => ready(Err(actix_web::error::ErrorUnauthorized("API Key not provided")))
        }
    }
}

// API Endpoints
#[post("/users")]
async fn create_user(
    state: web::Data<AppState>,
    user_req: web::Json<CreateUserRequest>,
) -> impl Responder {
    let api_key = generate_api_key();
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    
    let password_hash = argon2.hash_password(user_req.password.as_bytes(), &salt)
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
    club_req: web::Json<AddClubRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            match sqlx::query!(
                "INSERT INTO clubs (user_id, name, distance) VALUES ($1, $2, $3) RETURNING id",
                user_id,
                club_req.name,
                club_req.distance
            )
            .fetch_one(&state.db)
            .await
            {
                Ok(club) => HttpResponse::Ok().json(Club {
                    id: club.id,
                    user_id,
                    name: club_req.name.clone(),
                    distance: club_req.distance,
                }),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

#[delete("/clubs")]
async fn remove_club(
    state: web::Data<AppState>,
    club_req: web::Json<RemoveClubRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            match sqlx::query!(
                "DELETE FROM clubs WHERE id = $1 AND user_id = $2",
                club_req.club_id,
                user_id
            )
            .execute(&state.db)
            .await
            {
                Ok(result) if result.rows_affected() > 0 => HttpResponse::Ok().finish(),
                Ok(_) => HttpResponse::NotFound().finish(),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

#[get("/clubs")]
async fn get_all_clubs(
    state: web::Data<AppState>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            match sqlx::query_as!(
                Club,
                "SELECT id, user_id, name, distance FROM clubs WHERE user_id = $1",
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

#[get("/clubs/by-distance")]
async fn get_club_by_distance(
    state: web::Data<AppState>,
    distance_req: web::Json<GetClubByDistanceRequest>,
    api_key: ApiKey,
) -> impl Responder {
    match verify_api_key(&state.db, &api_key.0).await {
        Ok(user_id) => {
            let target_distance = distance_req.distance;
            let lower_bound = target_distance - 25;
            let upper_bound = target_distance + 25;

            match sqlx::query_as!(
                Club,
                "SELECT id, user_id, name, distance FROM clubs 
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
                        Club,
                        "SELECT id, user_id, name, distance FROM clubs 
                        WHERE user_id = $1 AND distance BETWEEN $2 AND $3
                        ORDER BY ABS(distance - $4)",
                        user_id,
                        lower_bound,
                        upper_bound,
                        target_distance
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                db: db_pool.clone(),
            }))
            .service(
                web::scope("")
                    .service(create_user)
                    .service(add_club)
                    .service(remove_club)
                    .service(get_all_clubs)
                    .service(get_club_by_distance)
            )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
