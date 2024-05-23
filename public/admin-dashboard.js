document.getElementById('video-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const title = document.getElementById('video-title').value;
    const url = document.getElementById('video-url').value;
    const description = document.getElementById('video-description').value;

    const video = { title, url, description };

    console.log('New video added:', video);


    document.getElementById('video-form').reset();
});

document.getElementById('logout').addEventListener('click', function() {
    window.location.href = 'admin-login.html';
});
