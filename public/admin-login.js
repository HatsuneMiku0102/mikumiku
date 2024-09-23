document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('login-form').addEventListener('submit', function (event) {
        event.preventDefault();
        const errorMessage = document.getElementById('error-message');
        errorMessage.textContent = '';
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (!username || !password) {
            errorMessage.textContent = 'Please fill in both fields';
            errorMessage.classList.add('active');
            setTimeout(() => {
                errorMessage.classList.remove('active');
            }, 3000);
            return;
        }
        errorMessage.textContent = 'Logging in...';
        errorMessage.classList.add('active');
        fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        })
        .then(response => {
            if (response.status === 401) {
                errorMessage.textContent = 'Invalid username or password';
                throw new Error('401 Unauthorized');
            } else if (!response.ok) {
                errorMessage.textContent = 'An error occurred. Please try again.';
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            if (data.auth && data.redirect) {
                window.location.href = data.redirect;
            } else {
                errorMessage.textContent = 'An error occurred. Please try again.';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            errorMessage.textContent = 'An error occurred during login. Please try again.';
        });
    });
});
