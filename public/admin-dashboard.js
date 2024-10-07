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
    }

    // Setup the socket connection to get real-time data
    const socket = io();

    socket.on('connect', () => {
        console.log('Socket connected successfully');
    });

    socket.on('connect_error', (error) => {
        console.error('Error connecting to socket:', error);
    });

    // Receive updated list of active users and display their IP information
    socket.on('activeUsersUpdate', (data) => {
        console.log('Active users data received:', data); // Log for debugging

        if (data && data.users && Array.isArray(data.users)) {
            const activeUsersCount = data.users.length;
            document.getElementById('active-users-count').innerText = `Currently Active Users: ${activeUsersCount}`;

            const ipList = document.getElementById('ip-list');
            ipList.innerHTML = '';  // Clear previous content

            // Create a set to keep track of unique IPs
            const uniqueIps = new Set();

            // Loop through the users array and display each user's IP info
            data.users.forEach(user => {
                // Check if the IP is already in the set
                if (!uniqueIps.has(user.ip)) {
                    uniqueIps.add(user.ip);
                    const locationInfo = `IP: ${user.ip}, City: ${user.city}, Region: ${user.region}, Country: ${user.country}`;
                    const ipItem = document.createElement('li');
                    ipItem.classList.add('ip-item');
                    ipItem.innerText = locationInfo;
                    ipList.appendChild(ipItem);
                }
            });
        } else {
            console.warn('No valid active users data found.');
            document.getElementById('active-users-count').innerText = 'No active users found.';
            document.getElementById('ip-list').innerHTML = '<li>No valid IP data available.</li>';
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
