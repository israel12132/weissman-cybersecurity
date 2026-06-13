use weissman_db::run_migrations;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("WEISSMAN_MIGRATE_URL")?;
    run_migrations(url.trim()).await?;
    println!("migrations ok");
    Ok(())
}
