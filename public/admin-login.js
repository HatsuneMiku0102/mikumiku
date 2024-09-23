document.addEventListener('DOMContentLoaded', function () {
    // Attach submit event to the login form
    document.getElementById('login-form').addEventListener('submit', function (event) {
        event.preventDefault();  // Prevent form from refreshing the page

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
            if (!response.ok) {
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            if (data.auth && data.redirect) {
                // Redirect to the randomized dashboard URL
                window.location.href = data.redirect;
            } else {
                document.getElementById('error-message').textContent = 'Invalid username or password';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('error-message').textContent = 'An error occurred. Please try again.';
        });
    });
});
