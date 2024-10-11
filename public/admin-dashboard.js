document.addEventListener('DOMContentLoaded', function() {
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

        // Socket.io connection
        const socket = io();

        // Listen for active users update
        socket.on('activeUsersUpdate', (data) => {
            console.log('Active users data received:', data);  // Log the received data for debugging
            document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.users.length}`;

            const ipList = document.getElementById('ip-list');
            ipList.innerHTML = '';  // Clear previous content

            data.users.forEach(user => {
                // Fetch location data from server using user IP
                fetch(`/api/location/${user.ip}`)
                    .then(response => response.json())
                    .then(locationData => {
                        if (locationData && !locationData.error) {
                            const locationInfo = `IP: ${user.ip}, City: ${locationData.city}, Region: ${locationData.region}, Country: ${locationData.country}`;
                            const ipItem = document.createElement('li');
                            ipItem.classList.add('ip-item');
                            ipItem.innerText = locationInfo;
                            ipList.appendChild(ipItem);
                        } else {
                            console.warn('Location data not found for IP:', user.ip);
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching location data:', error);
                    });
            });
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
    }
});
