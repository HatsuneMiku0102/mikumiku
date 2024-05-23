document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Basic authentication (in a real-world application, use server-side authentication)
    if (username === 'admin' && password === 'password') {
        window.location.href = 'admin-dashboard.html';
    } else {
        document.getElementById('error-message').textContent = 'Invalid username or password';
    }
});
