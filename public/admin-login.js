// public/admin-login.js
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const loadingSpinner = document.getElementById('loading-spinner');
    const loginButton = document.querySelector('.login-button');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent the default form submission

        // Clear previous messages
        errorMessage.style.display = 'none';
        successMessage.style.display = 'none';
        errorMessage.textContent = '';
        successMessage.textContent = '';

        // Get form values
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();

        // Basic front-end validation
        if (!username || !password) {
            errorMessage.textContent = 'Please enter both username and password.';
            errorMessage.style.display = 'block';
            return;
        }

        // Disable the login button and show loading spinner
        loginButton.disabled = true;
        loadingSpinner.style.display = 'block';

        try {
            // Send login request to server
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include', // Include cookies in the request
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok && data.auth) {
                // Display success message
                successMessage.textContent = 'Login successful! Redirecting...';
                successMessage.style.display = 'block';

                // Redirect to the admin dashboard after a short delay
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                // Display error message from server
                errorMessage.textContent = data.message || 'Invalid username or password.';
                errorMessage.style.display = 'block';
            }
        } catch (error) {
            console.error('Error during login:', error);
            errorMessage.textContent = 'An unexpected error occurred. Please try again later.';
            errorMessage.style.display = 'block';
        } finally {
            // Re-enable the login button and hide loading spinner
            loginButton.disabled = false;
            loadingSpinner.style.display = 'none';
        }
    });
});
