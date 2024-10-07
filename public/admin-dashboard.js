document.addEventListener('DOMContentLoaded', function () {
    console.log('Admin dashboard script loaded.');

    // Extract the 'token' cookie if available
    const cookieString = document.cookie;
    console.log('Current cookies:', cookieString);

    const token = cookieString
        .split('; ')
        .find(row => row.startsWith('token='))
        ?.split('=')[1];

    if (!token) {
        console.warn('No valid token found, redirecting to login page.');
        window.location.href = '/admin-login.html';
    } else {
        console.log('Valid token detected:', token);
    }

    // Connect to the socket server
    const socket = io();

    socket.on('connect', () => {
        console.log('Connected to socket server.');
    });

    socket.on('connect_error', (error) => {
        console.error('Error connecting to socket:', error);
    });

    // Listen for location updates from the server
    socket.on('locationUpdate', (data) => {
        console.log('Location data received:', data);
        
        const locationDiv = document.getElementById('location');
        if (locationDiv) {
            // Ensure there's content to display
            const locationInfo = `IP: ${data.ip}, City: ${data.city}, Region: ${data.region}, Country: ${data.country}`;
            const locationElement = document.createElement('p');
            locationElement.innerText = locationInfo;
            locationDiv.appendChild(locationElement);
        } else {
            console.warn('Location container not found on page.');
        }
    });

    // Logout logic
    document.getElementById('logout').addEventListener('click', () => {
        console.log('Logout initiated.');

        fetch('/logout', { method: 'POST', credentials: 'include' })
            .then(() => {
                console.log('Logout request successful, clearing token cookie.');
                // Clear the JWT token by setting its expiration to the past
                document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                // Redirect the user to the login page
                window.location.href = '/admin-login.html';
            })
            .catch(error => {
                console.error('Logout failed:', error);
            });
    });
});
