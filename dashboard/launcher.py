"""Starts the project's application from the console, with the agent attached, and keeps what it prints.

The person types or confirms the command in the console, the console runs it in the project folder with JAVA_TOOL_OPTIONS set so the JVM
loads the agent, and shows the output as it comes. Stop ends the whole process group, so a script that starts Java is ended with it.

Only a command that came from the person at the console is ever run. The Assistant, the configuration and the events can't supply one,
and a console that other machines can reach has no launcher at all. The command is remembered per project in .jot/run.json.
"""

import collections
import glob
import json
import os
import shlex
import signal
import socket
import subprocess
import threading
import time

import store

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_LINES = 2000                # lines of output kept
MAX_LINE = 2000                 # characters kept of one line
STOP_SECONDS = 8                # how long an application has to end before it is killed
RUN_FILE = "run.json"


def find_agent(home=None):
    """The agent jar, from JOT_AGENT_JAR, then ~/.jot/jot.jar, then the newest build next to this dashboard. None when there isn't one."""
    given = os.environ.get("JOT_AGENT_JAR")
    if given:
        return given if os.path.isfile(given) else None
    base = home or os.environ.get("JOT_HOME") or os.path.join(os.path.expanduser("~"), ".jot")
    installed = os.path.join(base, "jot.jar")
    if os.path.isfile(installed):
        return installed
    built = [p for p in glob.glob(os.path.join(HERE, "..", "target", "jot-*.jar")) if not os.path.basename(p).startswith("original-")]
    built.sort(key=os.path.getmtime, reverse=True)
    return os.path.abspath(built[0]) if built else None


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return None


def suggest(folder):
    """The commands that probably start the project, each with why, best guess first."""
    found = []

    def add(command, why):
        if command not in [c["command"] for c in found]:
            found.append({"command": command, "why": why})

    for script in ("run.sh", "start.sh", os.path.join("bin", "run.sh")):
        path = os.path.join(folder, script)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            add("./" + script, "the script the project starts with")
    pom = _read(os.path.join(folder, "pom.xml"))
    if pom is not None:
        wrapper = "./mvnw" if os.path.isfile(os.path.join(folder, "mvnw")) else "mvn"
        if "spring-boot" in pom:
            add(wrapper + " spring-boot:run", "a Maven project that uses Spring Boot")
    for name in ("build.gradle", "build.gradle.kts"):
        text = _read(os.path.join(folder, name))
        if text is not None:
            wrapper = "./gradlew" if os.path.isfile(os.path.join(folder, "gradlew")) else "gradle"
            if "org.springframework.boot" in text:
                add(wrapper + " bootRun", "a Gradle project that uses Spring Boot")
            elif "application" in text:
                add(wrapper + " run", "a Gradle application")
            break
    jars = []
    for pattern in ("target/*.jar", "build/libs/*.jar"):
        jars += [p for p in glob.glob(os.path.join(folder, pattern))
                 if not os.path.basename(p).startswith("original-") and not p.endswith(("-sources.jar", "-javadoc.jar", "-plain.jar"))]
    jars.sort(key=os.path.getmtime, reverse=True)
    if jars:
        add("java -jar " + os.path.relpath(jars[0], folder), "the newest jar that was built")
    return found


def _ps(field, pid):
    try:
        out = subprocess.run(["ps", "-o", field + "=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    return out


def _seconds(etime):
    """Seconds from the elapsed time ps prints, [[dd-]hh:]mm:ss."""
    try:
        days, _, rest = etime.rpartition("-")
        parts = [int(x) for x in rest.split(":")]
    except ValueError:
        return None
    total = 0
    for part in parts:
        total = total * 60 + part
    return total + (int(days) * 86400 if days else 0)


def running_elsewhere(db_path, now=None):
    """The applications that are writing this project's events and were not started from the console, which are still running on this machine.

    The events say which process wrote them, so the newest few are looked at, and one counts only when it is on this host, is a live Java
    process this person's account can signal, and was started before its last event. That last test is what tells it from some other
    program that was given the same process number after the application ended."""
    import store
    rows = store.run_query(db_path, "SELECT pid, host, app, run, MAX(ts) FROM events_raw WHERE pid IS NOT NULL GROUP BY run, pid "
                                    "ORDER BY MAX(ts) DESC LIMIT 6")["rows"]
    here = socket.gethostname().split(".")[0].lower()
    now = now if now is not None else time.time()
    found = []
    for pid, host, app, run, last in rows:
        try:
            pid = int(pid)
            os.kill(pid, 0)
        except (ValueError, OSError):
            continue                # not a number, gone, or not this account's to signal
        if (host or "").split(".")[0].lower() != here or "java" not in _ps("command", pid).lower():
            continue
        elapsed = _seconds(_ps("etime", pid))
        if elapsed is None or now - elapsed > last / 1000 + 2:
            continue
        found.append({"pid": pid, "app": app, "run": run, "last_ts": last, "started": now - elapsed})
    return found


def stop_elsewhere(db_path, pid):
    """Asks one of those applications to end, and says whether it had after a few seconds. Only a process that running_elsewhere finds can be
    asked, whatever number is given."""
    if pid not in [f["pid"] for f in running_elsewhere(db_path)]:
        raise store_error("that isn't an application this console can stop, it may have ended already", 404)
    os.kill(pid, signal.SIGTERM)
    end = time.time() + STOP_SECONDS
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.2)
    return False


def store_error(text, status):
    return store.SaveError(text, status)


class Launcher:
    """One application, started and stopped from the console, and its output."""

    def __init__(self, folder, jots_file=None, agent=None):
        self.folder, self.jots_file = folder, jots_file
        self.agent = agent if agent is not None else find_agent()
        self.where = store.jot_dir(jots_file, folder)
        self.lock = threading.Lock()
        self.proc = None
        self.thread = None
        self.command = self._remembered()
        self.started = None
        self.lines = collections.deque(maxlen=MAX_LINES)
        self.count = 0

    def _remembered(self):
        try:
            with open(os.path.join(self.where, RUN_FILE)) as f:
                command = json.load(f).get("command")
        except (OSError, ValueError, AttributeError):
            return None
        return command if isinstance(command, str) and command.strip() else None

    def _remember(self, command):
        try:
            os.makedirs(self.where, exist_ok=True)
            with open(os.path.join(self.where, RUN_FILE), "w") as f:
                json.dump({"command": command}, f)
        except OSError:
            pass            # the command is a convenience

    def _add(self, text):
        with self.lock:
            self.count += 1
            self.lines.append((self.count, text[:MAX_LINE]))

    def _pump(self, proc):
        for raw in proc.stdout:
            self._add(raw.rstrip("\r\n"))
        proc.stdout.close()

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def state(self, after=0):
        proc = self.proc
        with self.lock:
            lines = [[n, t] for n, t in self.lines if n > after]
            count = self.count
        code = proc.poll() if proc is not None else None
        return {"command": self.command, "running": proc is not None and code is None, "pid": proc.pid if proc is not None else None,
                "started": self.started, "exit_code": code, "lines": lines, "next": count, "agent": self.agent,
                "folder": self.folder, "suggestions": suggest(self.folder)}

    def start(self, command):
        if os.name == "nt":
            raise store.SaveError("starting the application from the console isn't supported on Windows yet", 400)
        text = (command or "").strip()
        if not text:
            raise store.QueryError("type the command that starts your application")
        try:
            argv = shlex.split(text)
        except ValueError as e:
            raise store.QueryError("can't read that command, %s" % e)
        if not self.agent:
            raise store.QueryError("the JOT agent jar wasn't found. Build it with mvn package, or put it at ~/.jot/jot.jar, "
                                   "or set JOT_AGENT_JAR to its path")
        flag = "-javaagent:" + self.agent + ("=" + self.jots_file if self.jots_file else "")
        if '"' in flag:
            raise store.QueryError("the agent and the jot.yaml can't have a double quote in their paths")
        if any(c.isspace() for c in flag):
            flag = '"%s"' % flag            # the JVM reads JAVA_TOOL_OPTIONS as words, and takes a quoted one whole
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                raise store.SaveError("the application is already running, stop it first", 409)
        env = dict(os.environ)
        env["JAVA_TOOL_OPTIONS"] = (env.get("JAVA_TOOL_OPTIONS", "") + " " + flag).strip()
        try:
            proc = subprocess.Popen(argv, cwd=self.folder, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", bufsize=1, start_new_session=True)
        except FileNotFoundError:
            raise store.QueryError("can't run %s, it wasn't found in %s" % (argv[0], self.folder))
        except OSError as e:
            raise store.QueryError("can't run %s, %s" % (argv[0], e.strerror or e))
        with self.lock:
            self.proc, self.command, self.started = proc, text, int(time.time() * 1000)
            self.lines.clear()
            self.count = 0
        self._add("$ " + text)
        self.thread = threading.Thread(target=self._pump, args=(proc,), daemon=True)
        self.thread.start()
        self._remember(text)
        return self.state()

    def stop(self):
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return self.state()
        self._signal(proc, signal.SIGTERM)
        try:
            proc.wait(STOP_SECONDS)
        except subprocess.TimeoutExpired:
            self._add("(still running after %d seconds, killed)" % STOP_SECONDS)
            self._signal(proc, signal.SIGKILL)
            proc.wait(2)
        if self.thread is not None:
            self.thread.join(2)
        return self.state()

    @staticmethod
    def _signal(proc, sig):
        try:
            os.killpg(proc.pid, sig)        # the process was started as the leader of its own group
        except (ProcessLookupError, PermissionError):
            pass

    def close(self):
        """Ends the application, which would otherwise be left running with nowhere to see its output."""
        try:
            self.stop()
        except Exception:
            pass
