// Your JavaScript code can go here
console.log("Welcome to MikuMiku <3");

document.addEventListener('DOMContentLoaded', function() {
    const videoContainer = document.getElementById('video-container');

    fetch('public/videos.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(videos => {
            if (videos && videos.length) {
                // Clear any previous "No videos available" message
                videoContainer.innerHTML = '';

                // Iterate through each video and create HTML elements
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
            } else {
                // If no videos available, display a message
                videoContainer.innerHTML = '<p>No videos available</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching video data:', error);
            videoContainer.innerHTML = '<p>Error loading videos</p>';
        });
});

