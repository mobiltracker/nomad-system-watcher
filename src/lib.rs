#![allow(dead_code)]
use std::{collections::HashMap, path::PathBuf};

use async_log_watcher::{LogWatcher, LogWatcherSignal};
use async_std::channel::Sender;

static NOMAD_DATA_DIR: &str = r"/opt/nomad";

struct OutputMeta {
    index: usize,
}

#[derive(Debug)]
struct Task {
    pub task_name: String,
    path: PathBuf,
    file_watcher: LogWatcher,
    file_watcher_channel: Option<Sender<LogWatcherSignal>>,
}

impl Task {
    async fn new(path: PathBuf) -> Self {
        let file_watcher = LogWatcher::new(&path);

        Self {
            task_name: path.to_str().unwrap().to_owned(),
            path,
            file_watcher,
            file_watcher_channel: None,
        }
    }
}

#[derive(Debug)]
struct AllocationDirectory {
    alloc_id: String,
    path: PathBuf,
    tasks: Vec<Task>,
}

impl AllocationDirectory {
    pub async fn new(alloc_id: &str, path: PathBuf) -> Result<Self, std::io::Error> {
        let dirs = std::fs::read_dir(&path)?;
        let mut tasks = Vec::new();

        for dir in dirs {
            let dir = dir.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

            if dir.file_type().unwrap().is_file() && !(dir.path().extension().unwrap() == "fifo") {
                tasks.push(Task::new(dir.path()).await);
            }
        }

        Ok(Self {
            alloc_id: alloc_id.to_owned(),
            tasks,
            path,
        })
    }
}

#[derive(Debug)]
struct NomadSystem {
    pub allocations: HashMap<String, AllocationDirectory>,
}

impl NomadSystem {
    pub async fn new(data_dir: &str) -> Result<Self, std::io::Error> {
        let dirs = std::fs::read_dir(data_dir)?;
        let mut state = HashMap::<String, AllocationDirectory>::new();

        for dir in dirs {
            let dir = dir.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

            if dir.file_type().unwrap().is_dir() {
                state.insert(
                    dir.path()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                    AllocationDirectory::new(&dir.path().to_string_lossy(), dir.path()).await?,
                );
            }
        }

        Ok(Self { allocations: state })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        path::Path,
    };

    use rand::Rng;

    use crate::NomadSystem;

    #[async_std::test]
    async fn start_system() {
        let (dirs, allocs) = setup_scenario("start_system");
        let system = NomadSystem::new("test-data/start_system").await.unwrap();

        assert_eq!(dirs.len(), 3);
        assert_eq!(allocs.len(), 30);

        for (idx, dir_allocs) in allocs.chunks(10).enumerate() {
            let dir = &dirs[idx];
            let alloc_dir = system.allocations.get(dir).unwrap();
            let mut system_tasks = alloc_dir
                .tasks
                .iter()
                .map(|t| {
                    let task_path = Path::new(&t.task_name);
                    task_path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .to_owned()
                        .unwrap()
                        .to_string()
                })
                .collect::<Vec<_>>();

            let mut expected = dir_allocs
                .iter()
                .flat_map(|s| vec![format!("{}.stderr", s), format!("{}.stdout", s)])
                .collect::<Vec<String>>();

            system_tasks.sort();
            expected.sort();

            assert_eq!(expected, system_tasks);
        }
    }

    fn setup_scenario(name: &str) -> (Vec<String>, Vec<String>) {
        if !Path::exists(Path::new("test-data")) {
            std::fs::create_dir("test-data").unwrap();
        }

        let full_path = Path::new("test-data").join(name);

        std::fs::remove_dir_all(&full_path).ok();
        std::fs::create_dir(&full_path).unwrap();

        let dir_1 = rand_string();
        let dir_2 = rand_string();
        let dir_3 = rand_string();

        (
            vec![dir_1.clone(), dir_2.clone(), dir_3.clone()],
            create_mock_alloc_dir(&dir_1, &full_path)
                .into_iter()
                .chain(create_mock_alloc_dir(&dir_2, &full_path).into_iter())
                .chain(create_mock_alloc_dir(&dir_3, &full_path).into_iter())
                .collect(),
        )
    }

    fn create_mock_alloc_dir(name: &str, path: &Path) -> Vec<String> {
        let full_path = Path::new(path).join(name);
        std::fs::create_dir(&full_path).unwrap();

        let mut collected = vec![];
        for _ in 0..10 {
            let file_name = rand_string();
            collected.push(file_name.clone());
            let stdout = format!("{}.stdout", file_name);
            let stderr = format!("{}.stderr", file_name);
            let stdout_fifo = format!("{}.stdout.fifo", file_name);
            let stderr_fifo = format!("{}.stderr.fifo", file_name);

            std::fs::File::create(Path::new(&full_path).join(stdout)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stderr)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stdout_fifo)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stderr_fifo)).unwrap();
        }

        collected
    }

    fn rand_string() -> String {
        let rand: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(50)
            .map(char::from)
            .collect();

        let mut hasher = DefaultHasher::new();
        rand.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
