/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateUser } from '../models/CreateUser';
import type { LoginUser } from '../models/LoginUser';
import type { UserResponse } from '../models/UserResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AuthService {
    /**
     * @param requestBody
     * @returns void
     * @throws ApiError
     */
    public static loginUser(
        requestBody: LoginUser,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/auth/login',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                401: `Unauthorized`,
                422: `Invalid input`,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static logout(): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/auth/logout',
        });
    }
    /**
     * @returns UserResponse User info retrieved successfully
     * @throws ApiError
     */
    public static me(): CancelablePromise<UserResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/auth/me',
            errors: {
                401: `Unauthorized`,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static refresh(): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/auth/refresh',
            errors: {
                401: `Unauthorized`,
            },
        });
    }
    /**
     * @param requestBody
     * @returns UserResponse User created successfully
     * @throws ApiError
     */
    public static createUser(
        requestBody: CreateUser,
    ): CancelablePromise<UserResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/auth/register',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                409: `Conflict`,
                422: `Invalid input`,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static verify(): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/auth/verify',
            errors: {
                401: `Unauthorized`,
            },
        });
    }
}
