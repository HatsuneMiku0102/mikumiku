document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'admin-login.html';
        return;
    }

    fetch('/api/videos', {
        headers: {
            'x-access-token': token
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to fetch videos');
        }
        return response.json();
    })
    .then(videos => {
        renderVideos(videos);
    })
    .catch(error => {
        console.error('Error:', error);
        window.location.href = 'admin-login.html';
    });

    document.getElementById('video-form').addEventListener('submit', function(event) {
        event.preventDefault();

        const title = document.getElementById('video-title').value;
        const url = document.getElementById('video-url').value;
        const description = document.getElementById('video-description').value;

        const video = { title, url: url.replace('youtu.be', 'youtube.com/embed'), description };

        fetch('/api/videos', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': token
            },
            body: JSON.stringify(video)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    console.error('Failed to add video:', data);
                    alert('Failed to add video: ' + (data.message || 'Unknown error'));
                    throw new Error('Failed to add video');
                });
            }
            return response.json();
        })
        .then(data => {
            alert('Video added successfully');
            document.getElementById('video-form').reset();
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to add video');
        });
    });

    document.getElementById('logout').addEventListener('click', function() {
        localStorage.removeItem('token');
        window.location.href = 'admin-login.html';
    });
});

function renderVideos(videos) {
    const videoContainer = document.getElementById('video-container');
    videoContainer.innerHTML = ''; // Clear previous content

    videos.forEach(video => {
        const videoItem = document.createElement('div');
        videoItem.classList.add('video-item');
        videoItem.innerHTML = `
            <iframe width="560" height="315" src="${video.url}" frameborder="0" allowfullscreen></iframe>
            <h3>${video.title}</h3>
            <p class="video-description">${video.description}</p>
        `;
        videoContainer.appendChild(videoItem);
    });
}
