document.addEventListener('DOMContentLoaded', function() {
    const activeUsersCountElement = document.getElementById('active-users-count');
    const logoutButton = document.getElementById('logout');

    // Establish socket connection
    if (typeof io !== 'undefined') {
        const socket = io();

        // Listen for 'activeUsersUpdate' event from the server
        socket.on('activeUsersUpdate', (data) => {
            if (activeUsersCountElement) {
                // Assuming data has a property named `count` containing the user count
                if (data && typeof data.count !== 'undefined') {
                    activeUsersCountElement.innerText = `Currently Active Users: ${data.count}`;
                } else {
                    console.warn('Received unexpected data structure for activeUsersUpdate:', data);
                }
            }
        });
    } else {
        console.error('Socket.IO library not found. Please make sure it is loaded correctly.');
    }

    // Logout button functionality
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            fetch('/logout', {
                method: 'POST',
                credentials: 'include' // Include cookies with the logout request
            })
            .then((response) => {
                if (!response.ok) {
                    throw new Error('Logout failed');
                }
                // Clear token cookie by setting an expired date
                document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                // Redirect to the login page after logout
                window.location.href = '/admin-login.html';
            })
            .catch(error => {
                console.error('Error during logout:', error);
                alert('An error occurred while logging out. Please try again.');
            });
        });
    } else {
        console.warn('Logout button not found in the DOM.');
    }
});
