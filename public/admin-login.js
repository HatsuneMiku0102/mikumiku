// public/admin-login.js
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const loadingSpinner = document.getElementById('loading-spinner');
    const loginButton = document.querySelector('.login-button');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        console.log('Login form submitted'); // Debugging log
    
        // Clear previous messages
        errorMessage.style.display = 'none';
        successMessage.style.display = 'none';
        errorMessage.textContent = '';
        successMessage.textContent = '';
    
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
    
        if (!username || !password) {
            console.log('Username or password missing'); // Debugging log
            errorMessage.textContent = 'Please enter both username and password.';
            errorMessage.style.display = 'block';
            return;
        }
    
        loginButton.disabled = true;
        loadingSpinner.style.display = 'block';
    
        try {
            console.log('Sending login request'); // Debugging log
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ username, password })
            });
    
            const data = await response.json();
            console.log('Response received', data); // Debugging log
    
            if (response.ok && data.auth) {
                successMessage.textContent = 'Login successful! Redirecting...';
                successMessage.style.display = 'block';
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                errorMessage.textContent = data.message || 'Invalid username or password.';
                errorMessage.style.display = 'block';
            }
        } catch (error) {
            console.error('Error during login:', error);
            errorMessage.textContent = 'An unexpected error occurred. Please try again later.';
            errorMessage.style.display = 'block';
        } finally {
            loginButton.disabled = false;
            loadingSpinner.style.display = 'none';
        }
    });
});
