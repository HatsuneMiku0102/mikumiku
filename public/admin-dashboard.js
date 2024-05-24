document.addEventListener('DOMContentLoaded', function() {

    fetch('/api/videos')
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
        const url = document.getElementById('video-url').value.replace('youtu.be', 'youtube.com/embed');
        const description = document.getElementById('video-description').value;

        const video = { title, url, description };

        fetch('/api/videos', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
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

            fetch('/api/videos')
                .then(response => response.json())
                .then(videos => {
                    renderVideos(videos);
                });
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to add video');
        });
    });


    document.getElementById('logout').addEventListener('click', function() {
        fetch('/logout', {
            method: 'POST'
        })
        .then(() => {
            window.location.href = 'admin-login.html';
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});

function renderVideos(videos) {
    const videoContainer = document.getElementById('video-container');
    if (!videoContainer) {
        console.error('Error: video-container element not found.');
        return;
    }

    videoContainer.innerHTML = ''; 

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
