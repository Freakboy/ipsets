const usernameInput = document.getElementById("usernameInput");
const passwordInput = document.getElementById("passwordInput");
const loginForm = document.getElementById("loginForm");
const loginButton = document.getElementById("loginButton");
const loginError = document.getElementById("loginError");

usernameInput.value = localStorage.getItem("ipsets.username") || "admin";

function nextURL() {
  const params = new URLSearchParams(location.search);
  const next = params.get("next") || "/";
  if (!next.startsWith("/") || next.startsWith("//")) return "/";
  return next;
}

function showError(message) {
  loginError.textContent = message;
  loginError.hidden = false;
}

async function login(event) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  loginError.hidden = true;
  if (!username || !password) {
    showError("请输入用户名和密码");
    return;
  }

  loginButton.disabled = true;
  loginButton.textContent = "登录中";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) throw new Error("用户名或密码不正确");
    localStorage.setItem("ipsets.username", username);
    location.href = nextURL();
  } catch (err) {
    showError(err.message || "登录失败");
    loginButton.disabled = false;
    loginButton.textContent = "登录";
  }
}

loginForm.addEventListener("submit", login);
loginButton.addEventListener("click", (event) => {
  if (event.detail !== 0) login(event);
});
