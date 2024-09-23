document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('login-form').addEventListener('submit', function (event) {
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
        .then(response => {
            if (response.status === 401) {
                document.getElementById('error-message').textContent = 'Invalid username or password';
                throw new Error('401 Unauthorized');
            } else if (!response.ok) {
                document.getElementById('error-message').textContent = 'An error occurred. Please try again.';
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            if (data.auth && data.redirect) {
                window.location.href = data.redirect;
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});
