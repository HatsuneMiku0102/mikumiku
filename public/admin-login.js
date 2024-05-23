document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        localStorage.setItem('auth', 'true');
        window.location.href = 'admin-dashboard.html';
    } else {
        document.getElementById('error-message').textContent = 'Invalid username or password';
    }
});
