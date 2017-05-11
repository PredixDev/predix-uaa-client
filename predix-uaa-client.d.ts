declare module "predix-uaa-client" {
    export function getToken(url: string, clientId: string, clientSecret: string, refreshToken?: string): Promise<IToken>;

    export function clearCache();

    export interface IToken {
        access_token: string;
        refresh_token: string;
        expire_time: string;
    }
}