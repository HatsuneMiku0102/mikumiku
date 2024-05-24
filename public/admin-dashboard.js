document.addEventListener('DOMContentLoaded', function() {
    // Fetch videos and render them
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

    // Add event listener to the video form
    document.getElementById('video-form').addEventListener('submit', function(event) {
        event.preventDefault();

        const formData = new FormData();
        formData.append('title', document.getElementById('video-title').value);
        formData.append('url', document.getElementById('video-url').value.replace('youtu.be', 'youtube.com/embed'));
        formData.append('description', document.getElementById('video-description').value);
        formData.append('video', document.getElementById('video-file').files[0]);

        fetch('/api/videos', {
            method: 'POST',
            body: formData
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

    // Add event listener to the logout button
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
