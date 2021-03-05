#![allow(dead_code)]
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

// static NOMAD_DATA_DIR: &str = r"/opt/nomad";

struct OutputMeta {
    index: usize,
}

#[derive(Debug, Clone)]
struct TaskLogFile {
    pub path: PathBuf,
}

impl TaskLogFile {
    pub fn new(path: PathBuf) -> Self {
        TaskLogFile { path }
    }
}

#[derive(Debug)]
struct NomadTask {
    pub task_name: OsString,
    path: PathBuf,
    pub logs: Vec<TaskLogFile>,
}

impl NomadTask {
    fn new(name: &OsStr, dir_path: PathBuf) -> Self {
        Self {
            task_name: name.to_os_string(),
            logs: vec![],
            path: dir_path,
        }
    }
}

#[derive(Debug)]
struct AllocationDirectory {
    alloc_id: String,
    path: PathBuf,
    tasks: HashMap<OsString, NomadTask>,
}

impl AllocationDirectory {
    pub async fn new(alloc_id: &str, alloc_dir_path: PathBuf) -> Result<Self, std::io::Error> {
        let dir = std::fs::read_dir(&alloc_dir_path)?;

        let mut tasks: HashMap<OsString, NomadTask> = HashMap::new();

        for dir in dir {
            let dir_entry =
                dir.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

            if dir_entry.file_type().unwrap().is_file()
                && !(dir_entry.path().extension().unwrap() == "fifo")
            {
                let name = &dir_entry.file_name();
                let name = AllocationDirectory::normalize_task_name(name.as_os_str()).ok_or_else(
                    || std::io::Error::new(std::io::ErrorKind::NotFound, "Missing file"),
                )?;

                tasks
                    .entry(name.to_owned())
                    .and_modify(|task| {
                        task.logs.push(TaskLogFile::new(dir_entry.path()));
                    })
                    .or_insert_with(|| {
                        let mut task = NomadTask::new(&name, alloc_dir_path.clone());
                        task.logs.push(TaskLogFile::new(dir_entry.path()));
                        task
                    });
            }
        }

        Ok(Self {
            alloc_id: alloc_id.to_owned(),
            tasks,
            path: alloc_dir_path,
        })
    }

    fn diff_state(&self) {}

    fn normalize_task_name(path: &OsStr) -> Option<OsString> {
        let path = PathBuf::from(path);
        if let Some(ext) = path.extension() {
            if ext == "stderr" || ext == "stdout" {
                return path.file_stem().map(|p| p.to_owned());
            }

            let ext_as_number = ext.to_str().map(|s| s.parse::<i32>().ok()).flatten();

            if let Some(_) = ext_as_number {
                return path
                    .file_stem()
                    .map(|p| Path::new(p).file_stem().map(|p| p.to_os_string()))
                    .flatten();
            }
        }

        return None;
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
        ffi::OsString,
        hash::{Hash, Hasher},
        path::Path,
        str::FromStr,
    };

    use rand::Rng;

    use crate::{AllocationDirectory, NomadSystem};

    #[test]
    fn normalize_task_name() {
        let task_name_1 = "foobar.stdout";
        let task_name_2 = "foobar.stdout.1";
        let task_name_3 = "foobar.stdout.2";
        let task_name_4 = "foobar.stderr";

        vec![task_name_1, task_name_2, task_name_3, task_name_4]
            .into_iter()
            .map(|f| {
                AllocationDirectory::normalize_task_name(&OsString::from_str(f).unwrap()).unwrap()
            })
            .for_each(|p| assert_eq!("foobar", p));
    }

    #[async_std::test]
    async fn start_system() {
        let (dirs, allocs) = setup_scenario("start_system");
        let system = NomadSystem::new("test-data/start_system").await.unwrap();

        assert_eq!(dirs.len(), 3);
        assert_eq!(allocs.len(), 30);

        for (idx, dir_allocs) in allocs.chunks(10).enumerate() {
            let dir = &dirs[idx];
            let alloc_dir = system.allocations.get(dir).unwrap();

            let mut task_names = alloc_dir
                .tasks
                .iter()
                .map(|t| {
                    let task_path = Path::new(&t.1.task_name);
                    task_path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .to_owned()
                        .unwrap()
                        .to_string()
                })
                .collect::<Vec<_>>();

            task_names.sort();
            let mut sorted_allocs = dir_allocs.to_vec();
            sorted_allocs.sort();
            // Task groups ok
            assert_eq!(sorted_allocs, task_names);

            let mut nomad_tasks_log_groups = alloc_dir
                .tasks
                .iter()
                .map(|i| i.1)
                .flat_map(|t| t.logs.clone())
                .map(|t| t.path.file_name().unwrap().to_str().unwrap().to_owned())
                .collect::<Vec<_>>();

            let mut expected_log_groups = dir_allocs
                .iter()
                .flat_map(|s| {
                    vec![
                        format!("{}.stdout", s),
                        format!("{}.stdout.1", s),
                        format!("{}.stdout.2", s),
                        format!("{}.stderr", s),
                        format!("{}.stderr.1", s),
                    ]
                })
                .collect::<Vec<String>>();

            nomad_tasks_log_groups.sort();
            expected_log_groups.sort();

            assert_eq!(expected_log_groups, nomad_tasks_log_groups);
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
            let stdout_1 = format!("{}.stdout.1", file_name);
            let stdout_2 = format!("{}.stdout.2", file_name);
            let stderr = format!("{}.stderr", file_name);
            let stderr_1 = format!("{}.stderr.1", file_name);
            let stdout_fifo = format!("{}.stdout.fifo", file_name);
            let stderr_fifo = format!("{}.stderr.fifo", file_name);

            std::fs::File::create(Path::new(&full_path).join(stdout)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stdout_1)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stdout_2)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stderr)).unwrap();
            std::fs::File::create(Path::new(&full_path).join(stderr_1)).unwrap();
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
