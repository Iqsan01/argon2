import userModel from "../models/user.model.js";
import argon2 from "argon2";
import { generateTokens } from "../middleware/authJWT.js"

//buat user baru
export const register = async (req, res, next) => {
    try {
        const { username, password, firstname, lastname } = req.body;
        if (!username || !password || !firstname || !lastname) {
            const err = new Error("Harap masukkan data yang valid.");
            err.statusCode = 400;
            throw err;
        }
        const hashPassword = await argon2.hash(password, { timeCost: 4, memoryCost: 2048, type: argon2.argon2id });
        const user = new userModel({
            username,
            password: hashPassword,
            firstname,
            lastname
        });
        await user.save();
        const tokens = await generateTokens(user._id);
        res.cookie("access_token", tokens.accessToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true,
        });
        res.cookie("refresh_token", tokens.refreshToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true,
        });
        res.status(201).json({ message: "User berhasil dibuat." });
    } catch (err) {
        next(err);
    }
};

//login user
export const loginUser = async (req, res, next) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            const err = new Error("Harap masukkan username dan password.");
            err.statusCode = 400;
            throw err;
        }
        const user = await userModel.findOne({ username });
        if (!user) {
            const err = new Error("User tidak ditemukan.");
            err.statusCode = 401;
            throw err;
        }
        const isMatch = await argon2.verify(user.password, password);
        if (!isMatch) {
            const err = new Error("Password tidak valid.");
            err.statusCode = 401;
            throw err;
        }

        const tokens = await generateTokens(user._id);
        res.cookie("access_token", tokens.accessToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true
        });
        res.cookie("refresh_token", tokens.refreshToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true
        });
        res.status(200).json({ message: "Login berhasil." });
    } catch (err) {
        next(err);
    }
}

export const logout = async (req, res, next) => {
    try {
        const userId = req.userId;
        await userModel.findByIdAndUpdate(userId, { refreshToken: "" });
        res.clearCookie("access_token", { httpOnly: true, sameSite: "none", secure: true });
        res.clearCookie("refresh_token", { httpOnly: true, sameSite: "none", secure: true });
        res.status(200).json({message: "Berhasil logout"});
    } catch (err) {
        next(err);
    }
}