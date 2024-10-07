document.addEventListener('DOMContentLoaded', () => {
    console.log('Admin login script loaded.');

    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const loadingSpinner = document.getElementById('loading-spinner');
    const loginButton = document.querySelector('.login-button');

    if (!loginForm) {
        console.error('Login form not found!');
        return;
    }

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent the default form submission
        console.log('Login form submitted.');

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
            console.warn('Username or password missing.');
            errorMessage.textContent = 'Please enter both username and password.';
            errorMessage.style.display = 'block';
            return;
        }

        // Disable the login button and show loading spinner
        loginButton.disabled = true;
        if (loadingSpinner) {
            loadingSpinner.style.display = 'block';
        }

        try {
            console.log('Sending login request to the server...');
            // Send login request to server
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // Include cookies in the request
                body: JSON.stringify({ username, password }),
            });

            console.log('Login response received, status:', response.status);

            if (!response.ok) {
                throw new Error(`Login failed with status code: ${response.status}`);
            }

            const data = await response.json();
            console.log('Response data:', data);

            if (data.auth) {
                // Display success message
                successMessage.textContent = 'Login successful! Redirecting...';
                successMessage.style.display = 'block';

                console.log('Login successful, redirecting to:', data.redirect);

                // Redirect to the admin dashboard after a short delay
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                // Display error message from server
                console.warn('Login failed:', data.message);
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
            if (loadingSpinner) {
                loadingSpinner.style.display = 'none';
            }
        }
    });
});
