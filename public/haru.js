document.addEventListener('DOMContentLoaded', function () {
    const chatBox = document.getElementById('chat-box');
    const closeChatButton = document.getElementById('close-chat');
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatContent = document.getElementById('chat-content');
    const personalityCircle = document.getElementById('personalityCircle'); 


    const openChat = () => {
        chatBox.style.display = 'flex';
    };


    const closeChat = () => {
        chatBox.style.display = 'none'; 
    };


    personalityCircle.addEventListener('click', openChat);


    closeChatButton.addEventListener('click', closeChat);


    sendMessageButton.addEventListener('click', async function () {
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getGPTResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    });


    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        messageElement.textContent = message;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight; 
    }


    async function getGPTResponse(message) {
        try {
            const response = await fetch('/api/gpt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });
            const data = await response.json();
            return data.message || 'Sorry, something went wrong.';
        } catch (error) {
            console.error('Error fetching GPT-4 response:', error);
            return 'Sorry, something went wrong.';
        }
    }
});
