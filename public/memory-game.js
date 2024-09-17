document.addEventListener('DOMContentLoaded', () => {
    const cardArray = [
        { name: 'symbol1', symbol: '🍎' },
        { name: 'symbol1', symbol: '🍎' },
        { name: 'symbol2', symbol: '🍌' },
        { name: 'symbol2', symbol: '🍌' },
        { name: 'symbol3', symbol: '🍇' },
        { name: 'symbol3', symbol: '🍇' },
        { name: 'symbol4', symbol: '🍉' },
        { name: 'symbol4', symbol: '🍉' }
    ];

   
    cardArray.sort(() => 0.5 - Math.random());

    const gameBoard = document.getElementById('game-board');
    const gameStatus = document.getElementById('game-status');
    let chosenCards = [];
    let chosenCardsIds = [];
    let matchedCards = [];

    function createBoard() {
        for (let i = 0; i < cardArray.length; i++) {
            const card = document.createElement('div');
            card.setAttribute('class', 'card hidden');
            card.setAttribute('data-id', i);
            card.innerHTML = '<span class="symbol hidden">' + cardArray[i].symbol + '</span>';
            card.addEventListener('click', flipCard);
            gameBoard.appendChild(card);
        }
    }

    function flipCard() {
        let cardId = this.getAttribute('data-id');
        if (chosenCardsIds.includes(cardId) || matchedCards.includes(cardId)) {
            return;
        }

        chosenCards.push(cardArray[cardId].name);
        chosenCardsIds.push(cardId);
        this.querySelector('.symbol').classList.remove('hidden');

        if (chosenCards.length === 2) {
            setTimeout(checkForMatch, 500);
        }
    }

    function checkForMatch() {
        const cards = document.querySelectorAll('.card');
        const optionOneId = chosenCardsIds[0];
        const optionTwoId = chosenCardsIds[1];

        if (chosenCards[0] === chosenCards[1]) {
            matchedCards.push(optionOneId, optionTwoId);
            if (matchedCards.length === cardArray.length) {
                gameStatus.textContent = 'Congratulations! You matched all the cards.';
                setTimeout(() => {
                   
                    document.getElementById('game-modal').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                }, 2000);
            }
        } else {
            setTimeout(() => {
                cards[optionOneId].querySelector('.symbol').classList.add('hidden');
                cards[optionTwoId].querySelector('.symbol').classList.add('hidden');
            }, 500);
        }

        chosenCards = [];
        chosenCardsIds = [];
    }

    createBoard();
});
