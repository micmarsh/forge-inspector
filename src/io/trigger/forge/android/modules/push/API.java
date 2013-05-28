package io.trigger.forge.android.modules.push;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

import com.kinvey.android.Client;
import com.kinvey.android.callback.KinveyUserCallback;
import com.kinvey.java.User;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;

public class API {
	private static Client kinveyClient = 
			new Client.Builder("kid_PVtSim6Wi5", "c429fbc2a46d4ac4930f67ef7e4f8a8e",
					ForgeApp.getActivity()).build();
	public static void loginToNative (final ForgeTask task,
			@ForgeParam("username") final String username,
			@ForgeParam("password") final String password) throws NoSuchAlgorithmException{
		loginUserAndInitPush(task, username, password);
	}
	
	private static void loginUserAndInitPush (final ForgeTask task, 
			final String username, final String password) throws NoSuchAlgorithmException {
		kinveyClient.user().login(username, Hash.sha1(password), new KinveyUserCallback (){
			@Override
			public void onFailure(Throwable arg0) {
				task.error(arg0);
			}
			@Override
			public void onSuccess(User arg0) {
				initializePush(task);
			}
		});
	}
	
	private static void initializePush (ForgeTask task) {
		Push.Settings settings = new Push.Settings(
				ForgeApp.getActivity(),
				new String[]{"VNhKLCGhQKm6Kih-hQPWnQ", "7l5Tpp8RQzew51WNuieBlA"},
				kinveyClient
			);
		Push.initializePush(settings, task);
	}
	
	private static class Hash {
		private static String bytesToHex(byte[] bytes){
			Formatter formatter = new Formatter();
	        for (byte b : bytes) formatter.format("%02x", b);
	        return formatter.toString();
		}
		private static byte[] digestString(String toHash) throws NoSuchAlgorithmException{
			MessageDigest md = MessageDigest.getInstance("SHA-1"); 
			md.update(toHash.getBytes());
			return md.digest();
		}
		public static String sha1 (String toHash) throws NoSuchAlgorithmException {
			byte [] bytes = digestString(toHash);
			return bytesToHex(bytes);
		}
	}
}
