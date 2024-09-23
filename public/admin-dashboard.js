document.addEventListener('DOMContentLoaded', function() {

    const socket = io(); 

    socket.on('activeUsersUpdate', (data) => {
        document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.count}`;
    });

    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            fetch('/logout', {
                method: 'POST'
            })
            .then(() => {
                document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                window.location.href = '/admin-login.html';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }
});
