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
        window.location.href = '/auth';
    } else {
        console.log('Valid token detected:', token);

        // Socket.io connection
        const socket = io();

        // Listen for active users update
        socket.on('activeUsersUpdate', (data) => {
            console.log('Active users data received:', data);
            document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.users.length}`;

            const ipList = document.getElementById('active-ip-list'); // Ensure you use the correct ID
            ipList.innerHTML = '';  // Clear previous content

            data.users.forEach(user => {
                const ipItem = createIpItem(user);
                ipList.appendChild(ipItem);
            });
        });

        // Helper function to create an IP list item
        function createIpItem(user) {
            const ipItem = document.createElement('li');
            ipItem.classList.add('ip-item');

            // Join connection types correctly
            const connectionTypes = Array.from(user.connectionTypes).join(', ');
            ipItem.innerText = `IP: ${user.ip}, Connection Types: ${connectionTypes}`;

            // Add block and unblock buttons
            const blockButton = document.createElement('button');
            blockButton.innerText = 'Block';
            blockButton.onclick = () => blockUser(user.ip);

            const unblockButton = document.createElement('button');
            unblockButton.innerText = 'Unblock';
            unblockButton.onclick = () => unblockUser(user.ip);

            ipItem.appendChild(blockButton);
            ipItem.appendChild(unblockButton);

            return ipItem;
        }

        function blockUser(ip) {
            socket.emit('blockUser', { ip }, (response) => {
                if (response.status === 'success') {
                    console.log(`User with IP ${ip} has been blocked.`);
                    alert(`User with IP ${ip} has been blocked.`);
                } else {
                    alert(`Failed to block user: ${response.message}`);
                }
            });
        }

        function unblockUser(ip) {
            socket.emit('unblockUser', { ip }, (response) => {
                if (response.status === 'success') {
                    console.log(`User with IP ${ip} has been unblocked.`);
                    alert(`User with IP ${ip} has been unblocked.`);
                } else {
                    alert(`Failed to unblock user: ${response.message}`);
                }
            });
        }

        // Logout logic
        document.getElementById('logout').addEventListener('click', () => {
            console.log('Logout initiated.');

            fetch('/logout', { method: 'POST', credentials: 'include' })
                .then(() => {
                    console.log('Logout request successful, clearing token cookie.');
                    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                    window.location.href = '/auth';
                })
                .catch(error => {
                    console.error('Logout failed:', error);
                });
        });
    }
});
