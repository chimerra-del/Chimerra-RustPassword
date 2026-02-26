use git2::{Repository, Signature};
use std::path::Path;
use anyhow::Result;

pub fn commit_changes(path: &str, message: &str) -> Result<()> {
    let repo_path = Path::new(path).parent().unwrap_or(Path::new("."));
    let repo = Repository::discover(repo_path)?;
    
    let mut index = repo.index()?;
    index.add_path(Path::new(path))?;
    index.write()?;
    
    let oid = index.write_tree()?;
    let tree = repo.find_tree(oid)?;
    
    let signature = Signature::now("Vault User", "vault@internal")?;
    let parent_commit = repo.head()?.peel_to_commit()?;
    
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &[&parent_commit],
    )?;
    
    Ok(())
}
