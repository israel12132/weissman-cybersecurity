use weissman_db::auth_rotation::rotate_weissman_auth_password_on_boot;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    weissman_db::env_bootstrap::load_process_environment();
    rotate_weissman_auth_password_on_boot().await?;
    println!("weissman_auth password rotation ok");
    Ok(())
}
