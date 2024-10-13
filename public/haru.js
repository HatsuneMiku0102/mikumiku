// public/js/chat.js

document.addEventListener('DOMContentLoaded', () => {
    const chatBox = document.getElementById('chat-box');
    const chatContent = document.getElementById('chat-content');
    const chatInput = document.getElementById('chat-input');
    const sendMessageButton = document.getElementById('send-message');
    const closeChatButton = document.querySelector('.chat-header .close-chat');
    const openChatButton = document.getElementById('open-chat');
    const chatLoading = document.getElementById('chat-loading'); // Loading spinner

    // Generate or retrieve a sessionId
    let sessionId = localStorage.getItem('sessionId');
    if (!sessionId) {
        sessionId = generateUUID();
        localStorage.setItem('sessionId', sessionId);
    }

    // Function to generate a simple UUID
    function generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0,
                  v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // Open Chat Function
    function openChat() {
        chatBox.classList.add('open');
        chatBox.classList.remove('closed');
        openChatButton.classList.add('hidden'); // Hide the floating chat button
        chatInput.focus();
    }

    // Close Chat Function
    function closeChat() {
        chatBox.classList.remove('open');
        chatBox.classList.add('closed');
        openChatButton.classList.remove('hidden'); // Show the floating chat button
    }

    // Append Message to Chat
    function appendMessage(content, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        const icon = className === 'bot-message' ? '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="#ffffff" class="bi bi-robot" viewBox="0 0 16 16"><path d="M2 4a2 2 0 0 1 2-2h1a1 1 0 0 1 1 1v1h6V3a1 1 0 0 1 1-1h1a2 2 0 0 1 2 2v1h-1v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5H2V4zm4.5 0h5a.5.5 0 0 0 0 1h-5a.5.5 0 0 0 0-1zm1 3a.5.5 0 0 0-.5.5V9h1v-1.5a.5.5 0 0 0-.5-.5zm-2 0a.5.5 0 0 0-.5.5V9h1v-1.5a.5.5 0 0 0-.5-.5zM4 5v1h1V5H4zm6 0v1h1V5H10zm-5.5 3a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z"/></svg>' 
                                          : '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="#ffffff" class="bi bi-person" viewBox="0 0 16 16"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm4-3a4 4 0 1 1-8 0 4 4 0 0 1 8 0z"/><path fill-rule="evenodd" d="M8 9a5 5 0 0 0-4.546 2.916A5.978 5.978 0 0 0 1 15a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1 5.978 5.978 0 0 0-2.454-3.084A5 5 0 0 0 8 9z"/></svg>';
        messageElement.innerHTML = `
            ${icon}
            <div class="message-content">${content}</div>
        `;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight;
    }

    // Send Message to Server
    async function sendMessage() {
        const message = chatInput.value.trim();
        if (message === '') return;

        appendMessage(message, 'user-message');
        chatInput.value = '';
        chatInput.disabled = true;
        sendMessageButton.disabled = true;
        chatLoading.classList.add('active'); // Show loading spinner

        try {
            const response = await fetch('/api/openai-chat', { // Ensure this matches your server endpoint
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message, sessionId }), // Include sessionId
            });

            if (!response.ok) {
                if (response.status === 429) {
                    appendMessage('You are sending messages too quickly. Please wait a moment.', 'bot-message');
                } else if (response.status === 400) {
                    appendMessage('Your message could not be processed. Please try again.', 'bot-message');
                } else {
                    appendMessage('Sorry, something went wrong. Please try again.', 'bot-message');
                }
                return;
            }

            const data = await response.json();
            const botResponse = data.response || 'Sorry, I couldn’t process that.';

            appendMessage(botResponse, 'bot-message');
        } catch (error) {
            console.error('Error:', error);
            appendMessage('Sorry, something went wrong. Please try again.', 'bot-message');
        } finally {
            chatInput.disabled = false;
            sendMessageButton.disabled = false;
            chatLoading.classList.remove('active'); // Hide loading spinner
            chatInput.focus();
        }
    }

    // Event Listeners
    sendMessageButton.addEventListener('click', sendMessage);

    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    closeChatButton.addEventListener('click', closeChat);
    openChatButton.addEventListener('click', openChat);

    // Accessibility: Close chat with Escape key when focused inside the chat
    chatBox.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeChat();
            openChatButton.focus();
        }
    });

    // Initialize chat as closed
    closeChat();
});
