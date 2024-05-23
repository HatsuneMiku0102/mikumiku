document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json().then(data => {
        if (!response.ok) {
            console.error('Login failed:', data);
            document.getElementById('error-message').textContent = data.message || 'Invalid username or password';
        } else {
            localStorage.setItem('token', data.token);
            window.location.href = 'admin-dashboard.html';
        }
    }))
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('error-message').textContent = 'Login failed';
    });
});
