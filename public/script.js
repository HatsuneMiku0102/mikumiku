// Your JavaScript code can go here
console.log("Welcome to MikuMiku <3");

fetch('public/videos.json')
    .then(response => response.json())
    .then(data => {
        const videoContainer = document.getElementById('video-container');
        if (data && data.length) {
            // Iterate through each video and create HTML elements
            data.forEach(video => {
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
    });

