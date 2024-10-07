document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); 

     
        errorMessage.style.display = 'none';

      
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();

        try {
           
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok && data.auth) {

                window.location.href = data.redirect;
            } else {

                errorMessage.textContent = data.message || 'Invalid username or password.';
                errorMessage.style.display = 'block';
            }
        } catch (error) {
            console.error('Error during login:', error);
            errorMessage.textContent = 'An unexpected error occurred. Please try again later.';
            errorMessage.style.display = 'block';
        }
    });
});
