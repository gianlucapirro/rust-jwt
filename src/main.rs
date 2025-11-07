use api::setup::build_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _app = build_app(None, None).await?;
    Ok(())
}