import jwt from "jsonwebtoken";
import argon2 from "argon2";
import userModel from "../models/user.model.js";

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

//funsi untuk menghasilkan access token
export const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, accessTokenSecret, { expiresIn: "30m" });
};

//fungsi untuk menghasilkan refresh token
export const generateRefreshToken = async () => {
    const refreshToken = await argon2.hash(Math.random().toString(), { timeCost: 2048, type: argon2.argon2id });
    return refreshToken;
};

//fungsi untuk memperbarui access token dan refresh token
export const refreshTokens = async (refreshToken) => {
    try {
        const payload = jwt.verify(refreshToken, refreshTokenSecret);
        const userId = payload.userId;
        const accessToken = generateAccessToken(userId);
        const newRefreshToken = await generateRefreshToken();

        //update refersh token pada database
        await userModel.findByIdAndUpdate(userId, { refreshToken: newRefreshToken });

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    } catch (err) {
        throw err;
    }
};

//fungsi untuk menghasilkan access token dan refresh token
export const generateTokens = async (userId) => {
    try {
        const accessToken = generateAccessToken(userId);
        const refreshToken = await generateRefreshToken();

        //simpan refresh token pada database
        await userModel.findByIdAndUpdate(userId, { refreshToken });

        return {
            accessToken,
            refreshToken
        };
    } catch (err) {
        throw err;
    }
};
