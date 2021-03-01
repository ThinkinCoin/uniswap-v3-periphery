// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.7.5;
pragma abicoder v2;

import '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';
import '@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol';

import './interfaces/IRouterImmutableState.sol';
import './interfaces/IRouterSwaps.sol';
import './libraries/PoolAddress.sol';
import './libraries/Path.sol';
import './libraries/SafeCast.sol';
import './libraries/TransferHelper.sol';
import './RouterValidation.sol';

/// @title Logic for trading
abstract contract RouterSwaps is IRouterImmutableState, IRouterSwaps, RouterValidation {
    using Path for bytes;
    using SafeCast for uint256;

    /// @dev The minimum value that can be returned from #getSqrtRatioAtTick, plus 1
    uint160 private constant MIN_SQRT_RATIO = 4295128739 + 1;
    /// @dev The maximum value that can be returned from #getSqrtRatioAtTick, minus 1
    uint160 private constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342 - 1;

    struct SwapCallbackData {
        bytes path;
        uint256 amountSlippage;
        address payer;
        address recipient;
    }

    /// @inheritdoc IRouterSwaps
    function exactInput(SwapParams calldata params) external override checkDeadline(params.deadline) {
        (address tokenA, address tokenB, uint24 fee) = params.path.decode();

        IUniswapV3Pool pool =
            IUniswapV3Pool(PoolAddress.computeAddress(this.factory(), PoolAddress.getPoolKey(tokenA, tokenB, fee)));

        address recipient = params.path.hasPairs() ? address(this) : params.recipient;
        bool zeroForOne = tokenA < tokenB;

        pool.swap(
            recipient,
            zeroForOne,
            params.amount.toInt256(),
            zeroForOne ? MIN_SQRT_RATIO : MAX_SQRT_RATIO,
            abi.encode(
                SwapCallbackData({
                    path: params.path,
                    amountSlippage: params.amountSlippage,
                    payer: msg.sender,
                    recipient: params.recipient
                })
            )
        );
    }

    /// @inheritdoc IRouterSwaps
    function exactOutput(SwapParams calldata params) external override checkDeadline(params.deadline) {
        (address tokenA, address tokenB, uint24 fee) = params.path.decode();

        IUniswapV3Pool pool =
            IUniswapV3Pool(PoolAddress.computeAddress(this.factory(), PoolAddress.getPoolKey(tokenA, tokenB, fee)));

        bool zeroForOne = tokenB < tokenA; // we're swapping in reverse

        pool.swap(
            params.recipient,
            zeroForOne,
            -params.amount.toInt256(), // negative number = exact output
            zeroForOne ? MIN_SQRT_RATIO : MAX_SQRT_RATIO,
            abi.encode(
                SwapCallbackData({
                    path: params.path,
                    amountSlippage: params.amountSlippage,
                    payer: msg.sender,
                    recipient: params.recipient
                })
            )
        );
    }

    /// @inheritdoc IUniswapV3SwapCallback
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        // decode the callback data
        SwapCallbackData memory swapCallbackData = abi.decode(data, (SwapCallbackData));

        // verify the callback
        (address tokenA, address tokenB, uint24 fee) = swapCallbackData.path.decode();
        verifyCallback(PoolAddress.getPoolKey(tokenA, tokenB, fee));

        bool exactIn = tokenA < tokenB ? amount0Delta > 0 : amount1Delta > 0; // flag for exact input
        int256 amountToPay = amount0Delta > 0 ? amount0Delta : amount1Delta;

        if (exactIn) {
            // pay
            if (swapCallbackData.payer != address(0)) {
                // for the first leg of exact input swaps, pay the pool from the swap initiator
                TransferHelper.safeTransferFrom(tokenA, swapCallbackData.payer, msg.sender, uint256(amountToPay));
                swapCallbackData.payer = address(0); // zero out the payer
            } else {
                // for subsequent legs, pay from this address
                TransferHelper.safeTransfer(tokenA, msg.sender, uint256(amountToPay));
            }

            // either forward or check
            int256 amountReceived = amount0Delta > 0 ? amount1Delta : amount0Delta;
            if (swapCallbackData.path.hasPairs()) {
                swapCallbackData.path = swapCallbackData.path.skipOne();
                forwardExactInput(amountReceived, swapCallbackData);
            } else {
                require(uint256(-amountReceived) >= swapCallbackData.amountSlippage, 'too little received');
            }
        } else {
            // either forward or check/pay
            if (swapCallbackData.path.hasPairs()) {
                swapCallbackData.path = swapCallbackData.path.skipOne();
                forwardExactOutput(amountToPay, swapCallbackData);
            } else {
                require(uint256(amountToPay) <= swapCallbackData.amountSlippage, 'too much requested');
                TransferHelper.safeTransferFrom(tokenB, swapCallbackData.payer, msg.sender, uint256(amountToPay));
            }
        }
    }

    function forwardExactInput(int256 amountReceived, SwapCallbackData memory swapCallbackData) private {
        (address tokenB, address tokenC, uint24 fee) = swapCallbackData.path.decode();

        // get the next pool
        IUniswapV3Pool nextPool =
            IUniswapV3Pool(PoolAddress.computeAddress(this.factory(), PoolAddress.getPoolKey(tokenB, tokenC, fee)));

        address recipient = swapCallbackData.path.hasPairs() ? address(this) : swapCallbackData.recipient;
        bool zeroForOne = tokenB < tokenC;

        require(-amountReceived > 0); // fairly hacky
        nextPool.swap(
            recipient,
            zeroForOne,
            -amountReceived,
            zeroForOne ? MIN_SQRT_RATIO : MAX_SQRT_RATIO,
            abi.encode(swapCallbackData)
        );
    }

    function forwardExactOutput(int256 amountToPay, SwapCallbackData memory swapCallbackData) private {
        (address tokenB, address tokenC, uint24 fee) = swapCallbackData.path.decode();

        // get the next pool
        IUniswapV3Pool nextPool =
            IUniswapV3Pool(PoolAddress.computeAddress(this.factory(), PoolAddress.getPoolKey(tokenB, tokenC, fee)));

        bool zeroForOne = tokenC < tokenB;

        nextPool.swap(
            msg.sender,
            zeroForOne,
            -amountToPay,
            zeroForOne ? MIN_SQRT_RATIO : MAX_SQRT_RATIO,
            abi.encode(swapCallbackData)
        );
    }
}