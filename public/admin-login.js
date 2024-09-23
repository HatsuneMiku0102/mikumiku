document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('login-form').addEventListener('submit', function (event) {
        event.preventDefault();  // Prevent form from refreshing the page

        // Clear any previous error messages
        document.getElementById('error-message').textContent = '';

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        // Add a check for empty fields
        if (!username || !password) {
            document.getElementById('error-message').textContent = 'Please fill in both fields';
            return;
        }

        // Show a loading message or spinner (optional)
        document.getElementById('error-message').textContent = 'Logging in...';

        // Perform the fetch request to the /login route
        fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })  // Sending plain password, backend will hash it with salt
        })
        .then(response => {
            // Handle different response cases
            if (response.status === 401) {
                document.getElementById('error-message').textContent = 'Invalid username or password';
                throw new Error('401 Unauthorized');
            } else if (!response.ok) {
                document.getElementById('error-message').textContent = 'An error occurred. Please try again.';
                throw new Error('Login failed');
            }
            return response.json();  // Parse the response as JSON
        })
        .then(data => {
            // If login is successful, redirect the user
            if (data.auth && data.redirect) {
                window.location.href = data.redirect;  // Redirect to the dashboard
            } else {
                document.getElementById('error-message').textContent = 'An error occurred. Please try again.';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            // Provide a fallback error message
            document.getElementById('error-message').textContent = 'An error occurred during login. Please try again.';
        });
    });
});
