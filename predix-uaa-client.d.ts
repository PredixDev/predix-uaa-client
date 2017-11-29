declare module "predix-uaa-client" {
    export function getToken(url: string, clientId: string, clientSecret: string, refreshToken?: string): Promise<IToken>;

    export function clearCache(key: string);

    export interface IToken {
        access_token: string;
        refresh_token: string;
        expire_time: number;
        renew_time: number;
        token_type: string;
    }
}
