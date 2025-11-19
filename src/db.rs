use mongodb::{Client, Database};
use std::env;

pub async fn init_db() -> Result<Database, mongodb::error::Error> {
    let uri = env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let db_name = env::var("DATABASE_NAME").unwrap_or_else(|_| "killcode".to_string());

    let client = Client::with_uri_str(&uri).await?;
    
    // Ping the database to verify connection
    client
        .database("admin")
        .run_command(mongodb::bson::doc! {"ping": 1})
        .await?;
    
    log::info!("Successfully connected to MongoDB");
    
    Ok(client.database(&db_name))
}
